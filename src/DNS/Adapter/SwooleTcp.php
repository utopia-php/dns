<?php

namespace Utopia\DNS\Adapter;

use Swoole\Runtime;
use Swoole\Server;
use Swoole\Server\Port;
use Utopia\DNS\Adapter;
use Utopia\DNS\Exception\Message\DecodingException as MessageDecodingException;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException as ProxyDecodingException;
use Utopia\DNS\TcpMessageStream;

/**
 * TCP-only DNS adapter built on Swoole.
 *
 * By default this constructs its own `Swoole\Server`. To co-host TCP
 * with UDP (e.g. alongside {@see SwooleUdp}) pass an externally managed
 * UDP server and this adapter attaches a TCP listener to it via
 * `addListener()` without owning the server lifecycle.
 *
 * Framing and PROXY preamble handling live entirely in userland via
 * {@see TcpMessageStream}, so Swoole's kernel-level
 * `open_length_check` optimization does not apply here. The cost is
 * negligible for typical DNS workloads, and the uniform model keeps
 * PROXY handling trivial to add.
 */
class SwooleTcp extends Adapter
{
    protected Server $server;

    protected Server|Port $port;

    protected bool $owned;

    /** @var array<int, TcpMessageStream> Per-fd message stream. */
    protected array $streams = [];

    /** @var callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string */
    protected mixed $onMessage;

    public function __construct(
        protected string $host = '0.0.0.0',
        protected int $tcpPort = 53,
        protected int $numWorkers = 1,
        protected int $maxCoroutines = 3000,
        ?Server $server = null,
    ) {
        if ($server === null) {
            $this->server = new Server($this->host, $this->tcpPort, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
            $this->server->set([
                'worker_num' => $this->numWorkers,
                'max_coroutine' => $this->maxCoroutines,
            ]);
            $this->port = $this->server;
            $this->owned = true;
        } else {
            $this->server = $server;
            $listener = $server->addListener($this->host, $this->tcpPort, SWOOLE_SOCK_TCP);
            if (!$listener instanceof Port) {
                throw new \RuntimeException('Could not add TCP listener to Swoole server.');
            }
            $this->port = $listener;
            $this->owned = false;
        }

        $this->port->set([
            'open_length_check' => false,
        ]);
    }

    public function onWorkerStart(callable $callback): void
    {
        $this->server->on('WorkerStart', function ($server, $workerId) use ($callback) {
            if (is_int($workerId)) {
                \call_user_func($callback, $workerId);
            }
        });
    }

    public function onMessage(callable $callback): void
    {
        $this->onMessage = $callback;

        $this->port->on('Connect', function (Server $server, int $fd) {
            $info = $server->getClientInfo($fd);
            $ip = is_array($info) && is_string($info['remote_ip'] ?? null) ? $info['remote_ip'] : '';
            $port = is_array($info) && is_int($info['remote_port'] ?? null) ? $info['remote_port'] : 0;

            $this->streams[$fd] = new TcpMessageStream(
                peerIp: $ip,
                peerPort: $port,
                enableProxyProtocol: $this->enableProxyProtocol,
            );
        });

        $this->port->on('Close', function (Server $server, int $fd) {
            unset($this->streams[$fd]);
        });

        $this->port->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) {
            $stream = $this->streams[$fd] ?? null;

            if ($stream === null) {
                $info = $server->getClientInfo($fd, $reactorId);
                $ip = is_array($info) && is_string($info['remote_ip'] ?? null) ? $info['remote_ip'] : '';
                $port = is_array($info) && is_int($info['remote_port'] ?? null) ? $info['remote_port'] : 0;

                $stream = new TcpMessageStream(
                    peerIp: $ip,
                    peerPort: $port,
                    enableProxyProtocol: $this->enableProxyProtocol,
                );
                $this->streams[$fd] = $stream;
            }

            try {
                foreach ($stream->feed($data) as [$message, $ip, $port]) {
                    $response = \call_user_func(
                        $this->onMessage,
                        $message,
                        $ip,
                        $port,
                        TcpMessageStream::MAX_MESSAGE_SIZE,
                    );

                    if ($response !== '') {
                        if (strlen($response) > TcpMessageStream::MAX_MESSAGE_SIZE) {
                            $server->close($fd);
                            return;
                        }
                        $server->send($fd, pack('n', strlen($response)) . $response);
                    }
                }
            } catch (ProxyDecodingException | MessageDecodingException) {
                $server->close($fd);
            }
        });
    }

    public function start(): void
    {
        if ($this->owned) {
            Runtime::enableCoroutine();
            $this->server->start();
        }
    }

    public function getName(): string
    {
        return 'swoole-tcp';
    }

    public function getServer(): Server
    {
        return $this->server;
    }
}
