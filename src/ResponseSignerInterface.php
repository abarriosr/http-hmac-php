<?php
/**
 * @file
 * Response Interface.
 */

namespace Acquia\Hmac;

use Acquia\Hmac\Response\ResponseInterface;

interface ResponseSignerInterface {
  /**
   * Generates a signature for the response given the secret key and algorithm.
   *
   * @param \Acquia\Hmac\Response\ResponseInterface $response
   * @param string $secretKey
   *
   * @return string
   */
  public function signResponse(ResponseInterface $response, $secretKey);

  /**
   * Returns the value of the "Authorization" header.
   *
   * @param \Acquia\Hmac\Response\ResponseInterface $response
   * @param string $id
   * @param string $secretKey
   *
   * @return string
   */
  public function getAuthorization(ResponseInterface $response, $id, $secretKey);

  /**
   * Gets the signature passed through the HTTP response.
   *
   * @param \Acquia\Hmac\Response\ResponseInterface $response
   *
   * @return \Acquia\Hmac\SignatureInterface
   */
  public function getSignature(ResponseInterface $response);

  /**
   * Returns the content type passed through the response.
   *
   * @param \Acquia\Hmac\Response\ResponseInterface $response
   *
   * @return string
   *
   * @throws \Acquia\Hmac\Exception\MalformedResponseException
   */
  public function getContentType(ResponseInterface $response);

  /**
   * Returns timestamp passed through the response.
   *
   * @param \Acquia\Hmac\Response\ResponseInterface $response
   *
   * @return string
   *
   * @throws \Acquia\Hmac\Exception\MalformedResponseException
   */
  public function getTimestamp(ResponseInterface $response);

  /**
   * Returns an associative array of custom headers.
   *
   * @param \Acquia\Hmac\Response\ResponseInterface $response
   *
   * @return string
   *
   * @throws \Acquia\Hmac\Exception\MalformedResponseException
   */
  public function getCustomHeaders(ResponseInterface $response);
} 