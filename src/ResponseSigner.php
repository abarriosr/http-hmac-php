<?php

namespace Acquia\Hmac;

use Acquia\Hmac\Response\ResponseInterface;

class ResponseSigner implements ResponseSignerInterface
{
    /**
     * @var \Acquia\Hmac\Digest\DigestInterface
     */
    protected $digest;

    /**
     * @var string
     */
    protected $provider = 'Acquia';

    /**
     * @var array
     */
    protected $timestampHeaders = array('Date');

    /**
     * @var array
     */
    protected $customHeaders = array();

    /**
     * @param \Acquia\Hmac\Digest\DigestInterface $digest
     */
    public function __construct(Digest\DigestInterface $digest = null)
    {
        $this->digest = $digest ?: new Digest\Version1();
    }

    /**
     * {@inheritDoc}
     *
     * @throws \Acquia\Hmac\Exception\MalformedResponse
     */
    public function getSignature(ResponseInterface $response)
    {
        if (!$response->hasHeader('Authorization')) {
            throw new Exception\MalformedResponseException('Authorization header required');
        }

        $provider = preg_quote($this->provider, '@');
        $pattern = '@^' . $provider . ' ([a-zA-Z0-9]+):([a-zA-Z0-9+/]+={0,2})$@';

        if (!preg_match($pattern, $response->getHeader('Authorization'), $matches)) {
            throw new Exception\MalformedResponseException('Authorization header not valid');
        }

        $time = $this->getTimestamp($response);
        $timestamp = strtotime($time);
        if (!$timestamp) {
            throw new Exception\MalformedResponseException('Timestamp not valid');
        }

        return new Signature($matches[1], $matches[2], $timestamp);
    }

    /**
     * {@inheritDoc}
     *
     * @throws \InvalidArgumentException
     * @throws \Acquia\Hmac\Exception\InvalidResponseException
     */
    public function signResponse(ResponseInterface $response, $secretKey)
    {
        return $this->digest->get($this, $response, $secretKey);
    }

    /**
     * {@inheritDoc}
     *
     * @throws \Acquia\Hmac\Exception\InvalidResponseException
     */
    public function getAuthorization(ResponseInterface $response, $id, $secretKey)
    {
        $signature = $this->signResponse($response, $secretKey);
        return $this->provider . ' ' . $id . ':' . $signature;
    }

    /**
     * @param string $provider
     *
     * @return \Acquia\Hmac\ResponseSigner
     */
    public function setProvider($provider)
    {
        $this->provider = $provider;
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Appends a timestap header to the stack.
     *
     * @param string $header
     *
     * @return \Acquia\Hmac\ResponseSigner
     */
    public function addTimestampHeader($header)
    {
        $this->timestampHeaders[] = $header;
        return $this;
    }

    /**
     * @param array $headers
     *
     * @return \Acquia\Hmac\ResponseSigner
     */
    public function setTimestampHeaders(array $headers)
    {
        $this->timestampHeaders = $headers;
        return $this;
    }

    /**
     * Append a custom headers to be used in the signature.
     *
     * @param string $header
     *
     * @return \Acquia\Hmac\ResponseSigner
     */
    public function addCustomHeader($header)
    {
        $this->customHeaders[] = $header;
        return $this;
    }

    /**
     * @param array $headers
     *
     * @return \Acquia\Hmac\ResponseSigner
     */
    public function setCustomHeaders(array $headers)
    {
        $this->customHeaders = $headers;
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getContentType(ResponseInterface $response)
    {
        if (!$response->hasHeader('Content-Type')) {
            throw new Exception\MalformedResponseException('Content type header required');
        }

        return $response->getHeader('Content-Type');
    }

    /**
     * {@inheritDoc}
     */
    public function getTimestamp(ResponseInterface $response)
    {
        foreach ($this->timestampHeaders as $header) {
            if ($response->hasHeader($header)) {
                return $response->getHeader($header);
            }
        }

        if (count($this->timestampHeaders) > 1) {
            $message = 'At least one of the following headers is required: ' . join(', ', $this->timestampHeaders);
        } else {
            $message = $this->timestampHeaders[0] . ' header required';
        }

        throw new Exception\MalformedResponseException($message);
    }

    /**
     * {@inheritDoc}
     */
    public function getCustomHeaders(ResponseInterface $response)
    {
        $headers = array();
        foreach ($this->customHeaders as $header) {
            if ($response->hasHeader($header)) {
                $headers[$header] = $response->getHeader($header);
            }
        }
        return $headers;
    }
}
