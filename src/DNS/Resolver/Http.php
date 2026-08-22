<?php

namespace Utopia\DNS\Resolver;

use Utopia\DNS\Http\Client;
use Utopia\DNS\Message;
use Utopia\DNS\Resolver;

/**
 * DNS over HTTPS Resolver
 *
 * A resolver that forwards DNS queries to a DoH server over HTTPS.
 * Implements RFC 8484 for DNS queries over HTTP/HTTPS.
 */
class Http implements Resolver
{
    protected Client $client;
    protected string $endpoint;

    /**
     * Create a new HTTP (DoH) resolver
     *
     * @param string $endpoint DoH endpoint URL (e.g., https://cloudflare-dns.com/dns-query)
     * @param int $timeout Total request timeout in seconds
     * @param int $connectTimeout Connection timeout in seconds
     * @param string $method HTTP method to use (GET or POST)
     */
    public function __construct(
        string $endpoint,
        int $timeout = 5,
        int $connectTimeout = 2,
        string $method = Client::METHOD_POST
    ) {
        $this->endpoint = $endpoint;
        $this->client = new Client($endpoint, $timeout, $connectTimeout, $method);
    }

    /**
     * Resolve DNS query by forwarding to the DoH server
     *
     * @param Message $query The DNS query message
     * @return Message The DNS response message
     */
    public function resolve(Message $query): Message
    {
        return $this->client->query($query);
    }

    /**
     * Get the name of the resolver
     *
     * @return string The resolver name
     */
    public function getName(): string
    {
        return "HTTP ($this->endpoint)";
    }

    /**
     * Get the underlying HTTP client
     *
     * @return Client The client instance
     */
    public function getClient(): Client
    {
        return $this->client;
    }
}
