<?php

namespace Utopia\DNS\Adapter;

use Utopia\DNS\Adapter;
use Swoole\Server;

class Swoole extends Adapter
{
    protected Server $server;
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
        $this->server = new Server($this->host, $this->port, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
    }

    /**
     * @param callable $callback
     */
    public function onPacket(callable $callback) {
        $this->server->on('Packet', function ($server, $data, $clientInfo) use ($callback) {
            $ip = $clientInfo['address'] ?? '';
            $port = $clientInfo['port'] ?? '';
            $answer = call_user_func($callback, $data, $ip, $port);

            $server->sendto($ip , $port , $answer);
        });
    }

    /**
     * Start the DNS server
     */
    public function start()
    {
        $this->server->start();
    }
}