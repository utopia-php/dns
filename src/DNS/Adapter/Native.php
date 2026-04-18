<?php

namespace Utopia\DNS\Adapter;

use Exception;
use Socket;
use Utopia\DNS\Adapter;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException as ProxyDecodingException;
use Utopia\DNS\ProxyProtocol;

class Native extends Adapter
{
    /**
     * Maximum DNS TCP message size per RFC 1035 Section 4.2.2
     * TCP uses 2-byte length prefix, so max payload is 65535 bytes
     */
    public const int MAX_TCP_MESSAGE_SIZE = 65535;

    protected Socket $udpServer;

    protected ?Socket $tcpServer = null;

    /** @var array<int, Socket> */
    protected array $tcpClients = [];

    /** @var array<int, string> */
    protected array $tcpBuffers = [];

    /** @var array<int, int> Track last activity time per TCP client for idle timeout */
    protected array $tcpLastActivity = [];

    /** @var array<int, bool> Whether the PROXY header has been consumed for this TCP client */
    protected array $tcpProxyParsed = [];

    /** @var array<int, array{ip: string, port: int}> Real client address (PROXY-aware) per TCP client */
    protected array $tcpClientAddress = [];

    /** @var callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string */
    protected mixed $onPacket;

    /** @var list<callable(int $workerId): void> */
    protected array $onWorkerStart = [];

    /**
     * @param string $host Host to bind to
     * @param int $port Port to listen on
     * @param bool $enableTcp Enable TCP support (RFC 5966)
     * @param int $maxTcpClients Maximum concurrent TCP clients
     * @param int $maxTcpBufferSize Maximum buffer size per TCP client
     * @param int $maxTcpFrameSize Maximum DNS message size over TCP
     * @param int $tcpIdleTimeout Seconds before idle TCP connections are closed (RFC 7766)
     * @param bool $enableProxyProtocol Auto-detect a PROXY protocol (v1 or v2) preamble on each connection/datagram. Connections without a preamble are treated as direct. Only enable when the listener is reachable solely from trusted proxies — untrusted clients could forge the source address.
     */
    public function __construct(
        protected string $host = '0.0.0.0',
        protected int $port = 8053,
        protected bool $enableTcp = true,
        protected int $maxTcpClients = 100,
        protected int $maxTcpBufferSize = 16384,
        protected int $maxTcpFrameSize = 65535,
        protected int $tcpIdleTimeout = 30,
        protected bool $enableProxyProtocol = false,
    ) {

        $server = \socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if (!$server) {
            throw new Exception('Could not start server.');
        }
        $this->udpServer = $server;

        if ($this->enableTcp) {
            $tcp = \socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            if (!$tcp) {
                throw new Exception('Could not start TCP server.');
            }

            socket_set_option($tcp, SOL_SOCKET, SO_REUSEADDR, 1);
            $this->tcpServer = $tcp;
        }
    }

    /**
     * Worker start callback
     *
     * @param callable(int $workerId): void $callback
     * @phpstan-param callable(int $workerId): void $callback
     */
    public function onWorkerStart(callable $callback): void
    {
        $this->onWorkerStart[] = $callback;
    }

    /**
     * @param callable $callback
     * @phpstan-param callable(string $buffer, string $ip, int $port, ?int $maxResponseSize):string $callback
     */
    public function onPacket(callable $callback): void
    {
        $this->onPacket = $callback;
    }

    /**
     * Start the DNS server
     */
    public function start(): void
    {
        if (socket_bind($this->udpServer, $this->host, $this->port) == false) {
            throw new Exception('Could not bind server to a server.');
        }

        if ($this->tcpServer) {
            if (socket_bind($this->tcpServer, $this->host, $this->port) == false) {
                throw new Exception('Could not bind TCP server.');
            }

            if (socket_listen($this->tcpServer, 128) == false) {
                throw new Exception('Could not listen on TCP server.');
            }

            socket_set_nonblock($this->tcpServer);
        }

        foreach ($this->onWorkerStart as $callback) {
            \call_user_func($callback, 0);
        }

        /** @phpstan-ignore-next-line */
        while (1) {
            // RFC 7766 Section 6.2.3: Close idle TCP connections
            $this->closeIdleTcpClients();

            $readSockets = [$this->udpServer];

            if ($this->tcpServer) {
                $readSockets[] = $this->tcpServer;
            }

            foreach ($this->tcpClients as $client) {
                $readSockets[] = $client;
            }

            $write = [];
            $except = [];

            // Use 1 second timeout for socket_select to periodically check idle connections
            $changed = socket_select($readSockets, $write, $except, 1);

            if ($changed === false || $changed === 0) {
                continue;
            }

            foreach ($readSockets as $socket) {
                if ($socket === $this->udpServer) {
                    $buf = '';
                    $ip = '';
                    $port = 0;
                    $len = socket_recvfrom($this->udpServer, $buf, 1024 * 4, 0, $ip, $port);

                    if ($len > 0 && is_string($buf) && is_string($ip) && is_int($port)) {
                        // Reply goes back to the actual UDP peer (the proxy), not the parsed client.
                        $replyIp = $ip;
                        $replyPort = $port;

                        if ($this->enableProxyProtocol && ProxyProtocol::detect($buf)) {
                            try {
                                $header = ProxyProtocol::decode($buf);
                            } catch (ProxyDecodingException) {
                                continue;
                            }

                            if ($header === null) {
                                continue;
                            }

                            if ($header->sourceAddress !== null && $header->sourcePort !== null) {
                                $ip = $header->sourceAddress;
                                $port = $header->sourcePort;
                            }

                            $buf = substr($buf, $header->bytesConsumed);
                        }

                        $answer = call_user_func($this->onPacket, $buf, $ip, $port, 512);

                        if ($answer !== '') {
                            socket_sendto($this->udpServer, $answer, strlen($answer), 0, $replyIp, $replyPort);
                        }
                    }

                    continue;
                }

                if ($this->tcpServer !== null && $socket === $this->tcpServer) {
                    $client = @socket_accept($this->tcpServer);

                    if ($client instanceof Socket) {
                        if (count($this->tcpClients) >= $this->maxTcpClients) {
                            @socket_close($client);
                            continue;
                        }

                        if (@socket_set_nonblock($client) === false) {
                            @socket_close($client);
                            continue;
                        }

                        socket_set_option($client, SOL_SOCKET, SO_KEEPALIVE, 1);
                        socket_set_option($client, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
                        socket_set_option($client, SOL_SOCKET, SO_SNDTIMEO, ['sec' => 5, 'usec' => 0]);

                        $id = spl_object_id($client);
                        $this->tcpClients[$id] = $client;
                        $this->tcpBuffers[$id] = '';
                        $this->tcpLastActivity[$id] = time();
                        $this->tcpProxyParsed[$id] = false;

                        $peerIp = '';
                        $peerPort = 0;
                        socket_getpeername($client, $peerIp, $peerPort);
                        $this->tcpClientAddress[$id] = [
                            'ip' => is_string($peerIp) ? $peerIp : '',
                            'port' => is_int($peerPort) ? $peerPort : 0,
                        ];
                    }

                    continue;
                }

                // Remaining readable sockets are TCP clients.
                $this->handleTcpClient($socket);
            }
        }
    }

    /**
     * Get the name of the adapter
     *
     * @return string
     */
    public function getName(): string
    {
        return 'native';
    }

    protected function handleTcpClient(Socket $client): void
    {
        $clientId = spl_object_id($client);

        $chunk = @socket_read($client, 8192, PHP_BINARY_READ);

        if ($chunk === '' || $chunk === false) {
            $error = socket_last_error($client);

            if ($chunk === '' || !in_array($error, [SOCKET_EAGAIN, SOCKET_EWOULDBLOCK], true)) {
                $this->closeTcpClient($client);
            }

            return;
        }

        // Update activity timestamp for idle timeout tracking
        $this->tcpLastActivity[$clientId] = time();

        $currentBufferSize = strlen($this->tcpBuffers[$clientId] ?? '');
        $chunkSize = strlen($chunk);

        if ($currentBufferSize + $chunkSize > $this->maxTcpBufferSize) {
            printf("TCP buffer size limit exceeded for client %d\n", $clientId);
            $this->closeTcpClient($client);
            return;
        }

        $this->tcpBuffers[$clientId] = ($this->tcpBuffers[$clientId] ?? '') . $chunk;

        if ($this->enableProxyProtocol && !($this->tcpProxyParsed[$clientId] ?? false)) {
            $detected = ProxyProtocol::detect($this->tcpBuffers[$clientId]);

            // Not enough bytes to decide yet; wait for more.
            if ($detected === null) {
                return;
            }

            if ($detected === 0) {
                // Definitely not a PROXY preamble — treat this connection as direct.
                $this->tcpProxyParsed[$clientId] = true;
            } else {
                try {
                    $header = ProxyProtocol::decode($this->tcpBuffers[$clientId]);
                } catch (ProxyDecodingException) {
                    $this->closeTcpClient($client);
                    return;
                }

                if ($header === null) {
                    // PROXY signature matched but payload is still incomplete.
                    return;
                }

                $this->tcpBuffers[$clientId] = substr($this->tcpBuffers[$clientId], $header->bytesConsumed);
                $this->tcpProxyParsed[$clientId] = true;

                if ($header->sourceAddress !== null && $header->sourcePort !== null) {
                    $this->tcpClientAddress[$clientId] = [
                        'ip' => $header->sourceAddress,
                        'port' => $header->sourcePort,
                    ];
                }
            }
        }

        while (strlen($this->tcpBuffers[$clientId]) >= 2) {
            $unpacked = unpack('n', substr($this->tcpBuffers[$clientId], 0, 2));
            $payloadLength = (is_array($unpacked) && array_key_exists(1, $unpacked) && is_int($unpacked[1])) ? $unpacked[1] : 0;

            // Close connection for invalid zero-length payloads
            if ($payloadLength === 0) {
                $this->closeTcpClient($client);
                return;
            }

            // DNS TCP messages have a 2-byte length prefix (max 65535), but we enforce
            // a stricter limit to prevent memory exhaustion from malicious clients
            if ($payloadLength > $this->maxTcpFrameSize) {
                printf("Invalid TCP frame size %d for client %d\n", $payloadLength, $clientId);
                $this->closeTcpClient($client);
                return;
            }

            if (strlen($this->tcpBuffers[$clientId]) < ($payloadLength + 2)) {
                return;
            }

            $message = substr($this->tcpBuffers[$clientId], 2, $payloadLength);
            $this->tcpBuffers[$clientId] = substr($this->tcpBuffers[$clientId], $payloadLength + 2);

            $address = $this->tcpClientAddress[$clientId] ?? null;

            if ($address === null) {
                $ip = '';
                $port = 0;
                socket_getpeername($client, $ip, $port);
                $address = [
                    'ip' => is_string($ip) ? $ip : '',
                    'port' => is_int($port) ? $port : 0,
                ];
            }

            $answer = call_user_func($this->onPacket, $message, $address['ip'], $address['port'], self::MAX_TCP_MESSAGE_SIZE);

            if ($answer !== '') {
                $this->sendTcpResponse($client, $answer);
            }
        }
    }

    /**
     * Send a TCP DNS response with length prefix.
     *
     * Per RFC 1035 Section 4.2.2, TCP messages use a 2-byte length prefix.
     * This limits maximum message size to 65535 bytes. Oversized responses
     * are rejected to prevent silent data corruption from integer overflow.
     */
    protected function sendTcpResponse(Socket $client, string $payload): void
    {
        $payloadLength = strlen($payload);

        // RFC 1035: TCP uses 2-byte length prefix, max 65535 bytes
        if ($payloadLength > self::MAX_TCP_MESSAGE_SIZE) {
            // This should not happen if truncation is working correctly
            // Log and close connection rather than send corrupted data
            printf(
                "TCP response too large (%d bytes > %d max), dropping\n",
                $payloadLength,
                self::MAX_TCP_MESSAGE_SIZE
            );
            $this->closeTcpClient($client);
            return;
        }

        $frame = pack('n', $payloadLength) . $payload;
        $total = strlen($frame);
        $sent = 0;

        while ($sent < $total) {
            $written = @socket_write($client, substr($frame, $sent));

            if ($written === false) {
                $error = socket_last_error($client);

                if (in_array($error, [SOCKET_EAGAIN, SOCKET_EWOULDBLOCK], true)) {
                    socket_clear_error($client);
                    usleep(1000);
                    continue;
                }

                $this->closeTcpClient($client);
                return;
            }

            $sent += $written;
        }
    }

    /**
     * Close idle TCP connections per RFC 7766 Section 6.2.3
     *
     * Servers should close idle connections to free resources.
     * This prevents resource exhaustion from slow or abandoned clients.
     */
    protected function closeIdleTcpClients(): void
    {
        $now = time();

        foreach ($this->tcpClients as $id => $client) {
            $lastActivity = $this->tcpLastActivity[$id] ?? 0;

            if (($now - $lastActivity) > $this->tcpIdleTimeout) {
                $this->closeTcpClient($client);
            }
        }
    }

    protected function closeTcpClient(Socket $client): void
    {
        $id = spl_object_id($client);

        unset(
            $this->tcpClients[$id],
            $this->tcpBuffers[$id],
            $this->tcpLastActivity[$id],
            $this->tcpProxyParsed[$id],
            $this->tcpClientAddress[$id],
        );

        @socket_close($client);
    }
}
