<?php

namespace Utopia\DNS\Adapter;

use Swoole\Runtime;
use Utopia\DNS\Adapter;
use Swoole\Server;
use Swoole\Server\Port;

class Swoole extends Adapter
{
    protected Server $server;

    protected ?Port $tcpPort = null;

    /** @var callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string */
    protected mixed $onPacket;

    protected string $host;
    protected int $port;

    protected bool $enableTcp;

    public function __construct(string $host = '0.0.0.0', int $port = 53, bool $enableTcp = true)
    {
        $this->host = $host;
        $this->port = $port;
        $this->enableTcp = $enableTcp;
        $this->server = new Server($this->host, $this->port, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);

        if ($this->enableTcp) {
            $this->tcpPort = $this->server->addListener($this->host, $this->port, SWOOLE_SOCK_TCP);

            $this->tcpPort->set([
                'open_length_check' => true,
                'package_length_type' => 'n',
                'package_length_offset' => 0,
                'package_body_offset' => 2,
                'package_max_length' => 65537,
            ]);
        }
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
     * @phpstan-param callable(string $buffer, string $ip, int $port, ?int $maxResponseSize):string $callback
     */
    public function onPacket(callable $callback): void
    {
        $this->onPacket = $callback;

        // UDP handler - enforces 512-byte limit per RFC 1035
        $this->server->on('Packet', function ($server, $data, $clientInfo) {
            $response = \call_user_func($this->onPacket, $data, $clientInfo['address'] ?? '', (int) ($clientInfo['port'] ?? 0), 512);

            if ($response !== '') {
                $server->sendto($clientInfo['address'], $clientInfo['port'], $response);
            }
        });

        // TCP handler - supports larger responses with length-prefixed framing per RFC 5966
        if ($this->tcpPort instanceof Port) {
            $this->tcpPort->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) {
                $info = $server->getClientInfo($fd, $reactorId) ?: [];
                $payload = substr($data, 2); // strip 2-byte length prefix
                $response = \call_user_func($this->onPacket, $payload, $info['remote_ip'] ?? '', $info['remote_port'] ?? 0, null);

                if ($response !== '') {
                    $server->send($fd, pack('n', strlen($response)) . $response);
                }
            });
        }
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
