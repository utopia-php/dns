<?php

namespace Utopia\DNS\Adapter;

use Exception;
use Socket;
use Utopia\DNS\Adapter;

class Native extends Adapter
{
    protected Socket $server;
    protected mixed $callback;
    protected string $host;
    protected int $port;

    /**
     * @param string $host
     * @param int $port
     */
    public function __construct(string $host = '0.0.0.0', int $port = 8053)
    {
        $this->host = $host;
        $this->port = $port;

        $server = \socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if (!$server) {
            throw new Exception('Could not start server.');
        }
        $this->server = $server;
    }

    public function onPacket(callable $callback): void
    {
        $this->callback = $callback;
    }

    /**
     * Start the DNS server
     */
    public function start(): void
    {
        if (socket_bind($this->server, $this->host, $this->port) == false) {
            throw new Exception('Could not bind server to a server.');
        }

        /** @phpstan-ignore-next-line */
        while (1) {
            $buf = '';
            $ip = '';
            $port = null;
            $len = socket_recvfrom($this->server, $buf, 1024 * 4, 0, $ip, $port);

            if ($len > 0) {
                $answer = call_user_func($this->callback, $buf, $ip, $port);

                if (socket_sendto($this->server, $answer, strlen($answer), 0, $ip, $port) === false) {
                    printf('Error in socket\n');
                }
            }
        }
    }

    /**
     * Get the name of the adapter
     *
     * @return string
     */
    public function getName(): string
    {
        return 'native';
    }
}
