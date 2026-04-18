<?php

namespace Utopia\DNS\Resolver;

use Utopia\DNS\DoHClient;
use Utopia\DNS\Message;
use Utopia\DNS\Resolver;

/**
 * DNS over HTTPS (DoH) Resolver
 *
 * A resolver that forwards DNS queries to a DoH server over HTTPS.
 * Implements RFC 8484 for DNS queries over HTTP/HTTPS.
 */
class DoH implements Resolver
{
    protected DoHClient $client;
    protected string $endpoint;

    /**
     * Create a new DoH resolver
     *
     * @param string $endpoint DoH endpoint URL (e.g., https://cloudflare-dns.com/dns-query)
     * @param int $timeout Request timeout in seconds
     * @param string $method HTTP method to use (GET or POST)
     */
    public function __construct(
        string $endpoint,
        int $timeout = 5,
        string $method = DoHClient::METHOD_POST
    ) {
        $this->endpoint = $endpoint;
        $this->client = new DoHClient($endpoint, $timeout, $method);
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
        return "DoH ($this->endpoint)";
    }

    /**
     * Get the DoH client instance
     *
     * @return DoHClient The client instance
     */
    public function getClient(): DoHClient
    {
        return $this->client;
    }
}
