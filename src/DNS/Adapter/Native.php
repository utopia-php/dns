<?php

namespace Utopia\DNS\Adapter;

use Socket;
use Utopia\DNS\Adapter;
use Utopia\CLI\Console;

class Native extends Adapter
{   
    protected Socket $server;
    protected $callback;
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
        $this->socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    }

    /**
     * @param callable $callback
     */
    public function onPacket(callable $callback) {
        $this->callback = $callback;
    }

    /**
     * Start the DNS server
     */
    public function start()
    {
        if ($this->socket < 0) {
            Console::error('Error in line %d', __LINE__ - 3);
            Console::exit();
        }

        if (socket_bind($this->socket, $this->host, $this->port) == false) {
            Console::error('Error in line %d', __LINE__ - 2);
            Console::exit();
        }

        while(1) {
            $buf = '';
            $ip = '';
            $port = null;
            $len = socket_recvfrom($this->socket, $buf, 1024*4, 0, $ip, $port);

            if ($len > 0) {
                $answer = call_user_func($this->callback, $buf, $ip, $port);

                if (socket_sendto($this->socket, $answer, strlen($answer), 0, $ip, $port) === false) {
                    printf('Error in socket\n');
                }
            }
        }
    }
}