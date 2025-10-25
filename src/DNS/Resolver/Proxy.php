<?php

namespace Utopia\DNS\Resolver;

use Utopia\DNS\Client;
use Utopia\DNS\Resolver;
use Utopia\DNS\Message;

class Proxy implements Resolver
{
    protected Client $client;
    protected string $server;
    protected int $port;

    /**
     * Create a new Proxy resolver
     *
     * @param string $server DNS server IP address
     * @param int $port DNS server port (default: 53)
     */
    public function __construct(string $server, int $port = 53)
    {
        $this->server = $server;
        $this->port = $port;
        $this->client = new Client($server, $port);
    }

    /**
     * Resolve DNS Record by proxying to another DNS server
     *
     * @param Message $query
     * @return Message
     */
    public function resolve(Message $query): Message
    {
        return $this->client->query($query);
    }

    /**
     * Get the name of the resolver
     *
     * @return string
     */
    public function getName(): string
    {
        return "Proxy ($this->server:$this->port)";
    }
}
