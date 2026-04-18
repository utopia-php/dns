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
    protected mixed $onUdpPacket;

    /** @var callable(int $fd, string $bytes, string $ip, int $port): void */
    protected mixed $onTcpReceive;

    /** @var callable(int $fd): void */
    protected mixed $onTcpClose;

    public function __construct(
        protected string $host = '0.0.0.0',
        protected int $port = 53,
        protected int $numWorkers = 1,
        protected int $maxCoroutines = 3000,
        protected bool $enableTcp = true,
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
                // TCP framing and PROXY parsing live in Server, so Swoole's
                // kernel-level length-check is not applicable here. The
                // cost (userland buffering) is negligible for DNS loads.
                $this->tcpPort->set([
                    'open_length_check' => false,
                ]);
            }
        }
    }

    public function onWorkerStart(callable $callback): void
    {
        $this->server->on('WorkerStart', function ($server, $workerId) use ($callback) {
            if (is_int($workerId)) {
                \call_user_func($callback, $workerId);
            }
        });
    }

    public function onUdpPacket(callable $callback): void
    {
        $this->onUdpPacket = $callback;

        $this->server->on('Packet', function ($server, $data, $clientInfo) {
            if (!is_string($data) || !is_array($clientInfo)) {
                return;
            }

            $ip = is_string($clientInfo['address'] ?? null) ? $clientInfo['address'] : '';
            $port = is_int($clientInfo['port'] ?? null) ? $clientInfo['port'] : 0;

            $response = \call_user_func($this->onUdpPacket, $data, $ip, $port, 512);

            if ($response !== '' && $server instanceof Server) {
                $server->sendto($ip, $port, $response);
            }
        });
    }

    public function onTcpReceive(callable $callback): void
    {
        $this->onTcpReceive = $callback;

        if (!$this->tcpPort instanceof Port) {
            return;
        }

        $this->tcpPort->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) {
            $info = $server->getClientInfo($fd, $reactorId);
            $ip = is_array($info) && is_string($info['remote_ip'] ?? null) ? $info['remote_ip'] : '';
            $port = is_array($info) && is_int($info['remote_port'] ?? null) ? $info['remote_port'] : 0;

            \call_user_func($this->onTcpReceive, $fd, $data, $ip, $port);
        });
    }

    public function onTcpClose(callable $callback): void
    {
        $this->onTcpClose = $callback;

        if (!$this->tcpPort instanceof Port) {
            return;
        }

        $this->tcpPort->on('Close', function (Server $server, int $fd) {
            \call_user_func($this->onTcpClose, $fd);
        });
    }

    public function sendTcp(int $fd, string $data): void
    {
        $this->server->send($fd, $data);
    }

    public function closeTcp(int $fd): void
    {
        $this->server->close($fd);
    }

    public function start(): void
    {
        Runtime::enableCoroutine();
        $this->server->start();
    }

    public function getName(): string
    {
        return 'swoole';
    }
}
