<?php

namespace Utopia\DNS\Adapter;

use Swoole\Runtime;
use Utopia\DNS\Adapter;
use Swoole\Server;
use Swoole\Server\Port;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException as ProxyDecodingException;
use Utopia\DNS\ProxyProtocol;

class Swoole extends Adapter
{
    /**
     * Maximum DNS TCP message size per RFC 1035 Section 4.2.2
     * TCP uses 2-byte length prefix, so max payload is 65535 bytes
     */
    public const int MAX_TCP_MESSAGE_SIZE = 65535;

    /** Hard cap when PROXY protocol is enabled, before the DNS length prefix can be validated. */
    public const int MAX_TCP_BUFFER_SIZE = 131072;

    protected Server $server;

    protected ?Port $tcpPort = null;

    /** @var callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string */
    protected mixed $onPacket;

    /**
     * Per-fd TCP state for PROXY-aware streams.
     *
     * @var array<int, array{buffer: string, proxied: bool, ip: string, port: int}>
     */
    protected array $tcpState = [];

    /**
     * @param bool $enableProxyProtocol Auto-detect a PROXY protocol (v1 or v2) preamble on each connection/datagram. Connections without a preamble are treated as direct. Only enable when the listener is reachable solely from trusted proxies — untrusted clients could forge the source address.
     */
    public function __construct(
        protected string $host = '0.0.0.0',
        protected int $port = 53,
        protected int $numWorkers = 1,
        protected int $maxCoroutines = 3000,
        protected bool $enableTcp = true,
        protected bool $enableProxyProtocol = false,
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

                if ($this->enableProxyProtocol) {
                    // Disable length-prefix framing: PROXY header sits before the DNS length prefix,
                    // so we must buffer and parse manually.
                    $this->tcpPort->set([
                        'open_length_check' => false,
                    ]);
                } else {
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

            $peerIp = is_string($clientInfo['address'] ?? null) ? $clientInfo['address'] : '';
            $peerPort = is_int($clientInfo['port'] ?? null) ? $clientInfo['port'] : 0;
            $ip = $peerIp;
            $port = $peerPort;
            $payload = $data;

            if ($this->enableProxyProtocol && ProxyProtocol::detect($payload)) {
                try {
                    $header = ProxyProtocol::decode($payload);
                } catch (ProxyDecodingException) {
                    return;
                }

                if ($header === null) {
                    return;
                }

                if ($header->sourceAddress !== null && $header->sourcePort !== null) {
                    $ip = $header->sourceAddress;
                    $port = $header->sourcePort;
                }

                $payload = substr($payload, $header->bytesConsumed);
            }

            $response = \call_user_func($this->onPacket, $payload, $ip, $port, 512);

            if ($response !== '' && $server instanceof Server) {
                // Reply goes back to the actual UDP peer (the proxy), not the parsed client.
                $server->sendto($peerIp, $peerPort, $response);
            }
        });

        if ($this->tcpPort instanceof Port) {
            if ($this->enableProxyProtocol) {
                $this->registerProxiedTcpHandlers();
            } else {
                $this->registerDirectTcpHandlers();
            }
        }
    }

    protected function registerDirectTcpHandlers(): void
    {
        $this->tcpPort?->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) {
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

    protected function registerProxiedTcpHandlers(): void
    {
        $port = $this->tcpPort;
        if (!$port instanceof Port) {
            return;
        }

        $port->on('Connect', function (Server $server, int $fd) {
            $info = $server->getClientInfo($fd);
            $ip = is_array($info) && is_string($info['remote_ip'] ?? null) ? $info['remote_ip'] : '';
            $portNum = is_array($info) && is_int($info['remote_port'] ?? null) ? $info['remote_port'] : 0;

            $this->tcpState[$fd] = [
                'buffer' => '',
                'proxied' => false,
                'ip' => $ip,
                'port' => $portNum,
            ];
        });

        $port->on('Close', function (Server $server, int $fd) {
            unset($this->tcpState[$fd]);
        });

        $port->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) {
            if (!isset($this->tcpState[$fd])) {
                $info = $server->getClientInfo($fd, $reactorId);
                $ip = is_array($info) && is_string($info['remote_ip'] ?? null) ? $info['remote_ip'] : '';
                $portNum = is_array($info) && is_int($info['remote_port'] ?? null) ? $info['remote_port'] : 0;

                $this->tcpState[$fd] = [
                    'buffer' => '',
                    'proxied' => false,
                    'ip' => $ip,
                    'port' => $portNum,
                ];
            }

            $state = &$this->tcpState[$fd];
            $state['buffer'] .= $data;

            if (strlen($state['buffer']) > self::MAX_TCP_BUFFER_SIZE) {
                $server->close($fd);
                return;
            }

            if (!$state['proxied']) {
                $detected = ProxyProtocol::detect($state['buffer']);

                // Not enough bytes to decide; wait for more.
                if ($detected === null) {
                    return;
                }

                if ($detected === 0) {
                    // Definitely not PROXY — treat as direct DNS on this connection.
                    $state['proxied'] = true;
                } else {
                    try {
                        $header = ProxyProtocol::decode($state['buffer']);
                    } catch (ProxyDecodingException) {
                        $server->close($fd);
                        return;
                    }

                    if ($header === null) {
                        return;
                    }

                    $state['buffer'] = substr($state['buffer'], $header->bytesConsumed);
                    $state['proxied'] = true;

                    if ($header->sourceAddress !== null && $header->sourcePort !== null) {
                        $state['ip'] = $header->sourceAddress;
                        $state['port'] = $header->sourcePort;
                    }
                }
            }

            while (strlen($state['buffer']) >= 2) {
                $unpacked = unpack('n', substr($state['buffer'], 0, 2));
                $payloadLength = (is_array($unpacked) && array_key_exists(1, $unpacked) && is_int($unpacked[1])) ? $unpacked[1] : 0;

                if ($payloadLength === 0 || $payloadLength > self::MAX_TCP_MESSAGE_SIZE) {
                    $server->close($fd);
                    return;
                }

                if (strlen($state['buffer']) < $payloadLength + 2) {
                    return;
                }

                $message = substr($state['buffer'], 2, $payloadLength);
                $state['buffer'] = substr($state['buffer'], $payloadLength + 2);

                $response = \call_user_func($this->onPacket, $message, $state['ip'], $state['port'], self::MAX_TCP_MESSAGE_SIZE);

                if ($response !== '') {
                    $server->send($fd, pack('n', strlen($response)) . $response);
                }
            }
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
