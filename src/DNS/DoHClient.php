<?php

namespace Utopia\DNS;

use Exception;

/**
 * DNS over HTTPS (DoH) Client
 *
 * Implements DNS queries over HTTPS as specified in RFC 8484.
 * Supports both GET and POST methods for sending DNS queries.
 */
class DoHClient
{
    public const METHOD_GET = 'GET';
    public const METHOD_POST = 'POST';

    /**
     * Create a new DoH client
     *
     * @param string $endpoint DoH endpoint URL (e.g., https://cloudflare-dns.com/dns-query)
     * @param int $timeout Request timeout in seconds
     * @param string $method HTTP method to use (GET or POST)
     */
    public function __construct(
        protected string $endpoint,
        protected int $timeout = 5,
        protected string $method = self::METHOD_POST
    ) {
        if (!filter_var($endpoint, FILTER_VALIDATE_URL)) {
            throw new Exception('Invalid DoH endpoint URL.');
        }

        if (!in_array($method, [self::METHOD_GET, self::METHOD_POST])) {
            throw new Exception('Invalid HTTP method. Use GET or POST.');
        }
    }

    /**
     * Send a DNS query over HTTPS
     *
     * @param Message $message The DNS query message
     * @return Message The DNS response message
     * @throws Exception On connection or protocol errors
     */
    public function query(Message $message): Message
    {
        if ($this->method === self::METHOD_GET) {
            return $this->queryGet($message);
        }

        return $this->queryPost($message);
    }

    /**
     * Send a DNS query using HTTP POST method
     *
     * RFC 8484 Section 4.1: POST request with application/dns-message body
     *
     * @param Message $message The DNS query message
     * @return Message The DNS response message
     */
    protected function queryPost(Message $message): Message
    {
        $packet = $message->encode();

        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL => $this->endpoint,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $packet,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/dns-message',
                'Accept: application/dns-message',
            ],
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        $errno = curl_errno($ch);

        curl_close($ch);

        if ($errno !== 0) {
            throw new Exception("DoH request failed: $error (Error code: $errno)");
        }

        if ($httpCode !== 200) {
            throw new Exception("DoH server returned HTTP $httpCode");
        }

        if (!is_string($response) || $response === '') {
            throw new Exception('Empty response received from DoH server');
        }

        return $this->decodeResponse($message, $response);
    }

    /**
     * Send a DNS query using HTTP GET method
     *
     * RFC 8484 Section 4.1: GET request with base64url-encoded dns parameter
     *
     * @param Message $message The DNS query message
     * @return Message The DNS response message
     */
    protected function queryGet(Message $message): Message
    {
        $packet = $message->encode();
        $encoded = $this->base64UrlEncode($packet);

        $separator = str_contains($this->endpoint, '?') ? '&' : '?';
        $url = $this->endpoint . $separator . 'dns=' . $encoded;

        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => [
                'Accept: application/dns-message',
            ],
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        $errno = curl_errno($ch);

        curl_close($ch);

        if ($errno !== 0) {
            throw new Exception("DoH request failed: $error (Error code: $errno)");
        }

        if ($httpCode !== 200) {
            throw new Exception("DoH server returned HTTP $httpCode");
        }

        if (!is_string($response) || $response === '') {
            throw new Exception('Empty response received from DoH server');
        }

        return $this->decodeResponse($message, $response);
    }

    /**
     * Decode the DNS response and validate the transaction ID
     *
     * @param Message $query Original query message
     * @param string $payload Raw response data
     * @return Message Decoded response message
     */
    protected function decodeResponse(Message $query, string $payload): Message
    {
        $response = Message::decode($payload);

        if ($response->header->id !== $query->header->id) {
            throw new Exception(
                "Mismatched DNS transaction ID. Expected {$query->header->id}, got {$response->header->id}"
            );
        }

        return $response;
    }

    /**
     * Encode data using base64url encoding (RFC 4648 Section 5)
     *
     * This is required for the GET method as per RFC 8484 Section 4.1
     *
     * @param string $data Binary data to encode
     * @return string Base64url-encoded string (no padding)
     */
    protected function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Get the DoH endpoint URL
     *
     * @return string The endpoint URL
     */
    public function getEndpoint(): string
    {
        return $this->endpoint;
    }

    /**
     * Get the HTTP method being used
     *
     * @return string The HTTP method (GET or POST)
     */
    public function getMethod(): string
    {
        return $this->method;
    }
}
