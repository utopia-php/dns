<?php

namespace Utopia\DNS\Adapter;

use Swoole\Runtime;
use Utopia\DNS\Adapter;
use Swoole\Server;
use Swoole\Server\Port;

class Swoole extends Adapter
{
    protected Server $server;

    protected ?Port $udpPort = null;

    /** @var callable(string $buffer, string $ip, int $port): string */
    protected mixed $onPacket;

    protected string $host;
    protected int $port;

    public function __construct(string $host = '0.0.0.0', int $port = 53)
    {
        $this->host = $host;
        $this->port = $port;
        $this->server = new Server($this->host, $this->port, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);

        $this->server->set([
            'open_length_check' => true,
            'package_length_type' => 'n',
            'package_length_offset' => 0,
            'package_body_offset' => 2,
            'package_max_length' => 65537,
        ]);

        $this->udpPort = $this->server->addlistener($this->host, $this->port, SWOOLE_SOCK_UDP);
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

        if ($this->udpPort instanceof Port) {
            $this->udpPort->on('Packet', function ($server, $data, $clientInfo) {
                $ip = $clientInfo['address'] ?? '';
                $port = (int) ($clientInfo['port'] ?? 0);
                $answer = \call_user_func($this->onPacket, $data, $ip, $port);

                // Swoole UDP sockets reject zero-length payloads; skip responding instead.
                if ($answer === '') {
                    return;
                }

                $server->sendto($ip, $port, $answer);
            });
        }

        $this->server->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) {
            $info = $server->getClientInfo($fd, $reactorId) ?: [];
            $ip = $info['remote_ip'] ?? '';
            $port = $info['remote_port'] ?? 0;

            $payload = substr($data, 2); // strip 2-byte length prefix
            $answer = \call_user_func($this->onPacket, $payload, $ip, $port);

            if ($answer === '') {
                return;
            }

            $frame = pack('n', strlen($answer)) . $answer;
            $server->send($fd, $frame);
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
