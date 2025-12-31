<?php

namespace Utopia\DNS\Adapter;

use Swoole\Runtime;
use Utopia\DNS\Adapter;
use Swoole\Server;
use Swoole\Server\Port;

class Swoole extends Adapter
{
    /**
     * Maximum DNS TCP message size per RFC 1035 Section 4.2.2
     * TCP uses 2-byte length prefix, so max payload is 65535 bytes
     */
    public const int MAX_TCP_MESSAGE_SIZE = 65535;

    protected Server $server;

    protected ?Port $tcpPort = null;

    /** @var callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string */
    protected mixed $onPacket;

    public function __construct(
        protected string $host = '0.0.0.0',
        protected int $port = 53,
        protected int $numWorkers = 1,
        protected int $maxCoroutines = 3000,
        protected bool $enableTcp = true
    ) {
        $this->server = new Server($this->host, $this->port, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
        $this->server->set([
            'worker_num' => $this->numWorkers,
            'max_coroutine' => $this->maxCoroutines,
        ]);

        if ($this->enableTcp) {
            $port = $this->server->addListener($this->host, $this->port, SWOOLE_SOCK_TCP);

            if ($port instanceof Port) {
                $this->tcpPort = $port;
                $this->tcpPort->set([
                    'open_length_check' => true,
                    'package_length_type' => 'n',
                    'package_length_offset' => 0,
                    'package_body_offset' => 2,
                    'package_max_length' => 65537,
                ]);
            }
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
            if (is_int($workerId)) {
                \call_user_func($callback, $workerId);
            }
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
            if (!is_string($data) || !is_array($clientInfo)) {
                return;
            }

            $ip = is_string($clientInfo['address'] ?? null) ? $clientInfo['address'] : '';
            $port = is_int($clientInfo['port'] ?? null) ? $clientInfo['port'] : 0;

            $response = \call_user_func($this->onPacket, $data, $ip, $port, 512);

            if ($response !== '' && $server instanceof Server) {
                $server->sendto($ip, $port, $response);
            }
        });

        // TCP handler - supports larger responses with length-prefixed framing per RFC 5966
        if ($this->tcpPort instanceof Port) {
            $this->tcpPort->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) {
                $info = $server->getClientInfo($fd, $reactorId);
                if (!is_array($info)) {
                    return;
                }

                $payload = substr($data, 2); // strip 2-byte length prefix
                $ip = is_string($info['remote_ip'] ?? null) ? $info['remote_ip'] : '';
                $port = is_int($info['remote_port'] ?? null) ? $info['remote_port'] : 0;

                $response = \call_user_func($this->onPacket, $payload, $ip, $port, self::MAX_TCP_MESSAGE_SIZE);

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
