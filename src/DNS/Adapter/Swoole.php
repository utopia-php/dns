<?php

namespace Utopia\DNS\Adapter;

use Swoole\Runtime;
use Utopia\DNS\Adapter;
use Swoole\Server;

class Swoole extends Adapter
{
    protected Server $server;

    /** @var callable(string $buffer, string $ip, int $port): string */
    protected mixed $onPacket;

    protected string $host;
    protected int $port;

    public function __construct(string $host = '0.0.0.0', int $port = 53)
    {
        $this->host = $host;
        $this->port = $port;
        $this->server = new Server($this->host, $this->port, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
    }

    /**
     * Worker start callback
     *
     * @param callable(int $workerId): void $callback
     */
    public function onWorkerStart(callable $callback): void
    {
        $this->server->on('WorkerStart', function ($server, $workerId) use ($callback) {
            \call_user_func($callback, $workerId);
        });
    }

    /**
     * @param callable $callback
     * @phpstan-param callable(string $buffer, string $ip, int $port):string $callback
     */
    public function onPacket(callable $callback): void
    {
        $this->onPacket = $callback;

        $this->server->on('Packet', function ($server, $data, $clientInfo) {
            $ip = $clientInfo['address'] ?? '';
            $port = $clientInfo['port'] ?? '';
            $answer = \call_user_func($this->onPacket, $data, $ip, $port);

            // Swoole UDP sockets reject zero-length payloads; skip responding instead.
            if ($answer === '') {
                return;
            }

            $server->sendto($ip, $port, $answer);
        });
    }

    /**
     * Start the DNS server
     */
    public function start(): void
    {
        Runtime::enableCoroutine();
        $this->server->start();
    }

    /**
     * Get the name of the adapter
     *
     * @return string
     */
    public function getName(): string
    {
        return 'swoole';
    }
}
