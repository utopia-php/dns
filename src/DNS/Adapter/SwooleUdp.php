<?php

namespace Utopia\DNS\Adapter;

use Swoole\Runtime;
use Swoole\Server;
use Utopia\DNS\Adapter;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException as ProxyDecodingException;
use Utopia\DNS\ProxyProtocolStream;

/**
 * UDP-only DNS adapter built on Swoole.
 *
 * By default this constructs its own `Swoole\Server`. To co-host UDP
 * with TCP (e.g. alongside {@see SwooleTcp}) pass an externally managed
 * server and set `$owned` to false so this adapter attaches handlers
 * without trying to start or stop the underlying server.
 */
class SwooleUdp extends Adapter
{
    /** RFC 1035: unicast UDP DNS messages are capped at 512 bytes. */
    public const int UDP_MAX_MESSAGE_SIZE = 512;

    protected Server $server;

    protected bool $owned;

    /** @var callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string */
    protected mixed $onMessage;

    public function __construct(
        protected string $host = '0.0.0.0',
        protected int $port = 53,
        protected int $numWorkers = 1,
        protected int $maxCoroutines = 3000,
        ?Server $server = null,
    ) {
        if ($server === null) {
            $this->server = new Server($this->host, $this->port, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
            $this->server->set([
                'worker_num' => $this->numWorkers,
                'max_coroutine' => $this->maxCoroutines,
            ]);
            $this->owned = true;
        } else {
            $this->server = $server;
            $this->owned = false;
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

    public function onMessage(callable $callback): void
    {
        $this->onMessage = $callback;

        $this->server->on('Packet', function ($server, $data, $clientInfo) {
            if (!is_string($data) || !is_array($clientInfo)) {
                return;
            }

            $peerIp = is_string($clientInfo['address'] ?? null) ? $clientInfo['address'] : '';
            $peerPort = is_int($clientInfo['port'] ?? null) ? $clientInfo['port'] : 0;
            $ip = $peerIp;
            $port = $peerPort;
            $payload = $data;

            if ($this->enableProxyProtocol) {
                try {
                    $header = ProxyProtocolStream::unwrapDatagram($payload);
                } catch (ProxyDecodingException) {
                    return;
                }

                if ($header !== null && $header->sourceAddress !== null && $header->sourcePort !== null) {
                    $ip = $header->sourceAddress;
                    $port = $header->sourcePort;
                }
            }

            $response = \call_user_func($this->onMessage, $payload, $ip, $port, self::UDP_MAX_MESSAGE_SIZE);

            if ($response !== '' && $server instanceof Server) {
                // Reply goes back to the actual UDP peer (the proxy), not the parsed client.
                $server->sendto($peerIp, $peerPort, $response);
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
        return 'swoole-udp';
    }

    public function getServer(): Server
    {
        return $this->server;
    }
}
