<?php

namespace Utopia\DNS\Adapter;

use Exception;
use Socket;
use Utopia\DNS\Adapter;
use Utopia\DNS\Exception\Message\DecodingException as MessageDecodingException;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException as ProxyDecodingException;
use Utopia\DNS\TcpMessageStream;

/**
 * TCP-only DNS adapter (RFC 1035 § 4.2.2, RFC 5966, RFC 7766) built on
 * PHP's `ext-sockets`.
 *
 * Each accepted connection is tracked with a {@see TcpMessageStream}
 * that handles buffering, optional PROXY preamble resolution, and
 * length-prefix framing. Complete DNS messages are delivered to the
 * registered {@see Adapter::onMessage()} callback; responses are
 * framed and written back on the same connection.
 */
class NativeTcp extends Adapter
{
    /** @var array<int, Socket> Active client sockets keyed by spl_object_id. */
    protected array $clients = [];

    /** @var array<int, TcpMessageStream> Per-client message stream. */
    protected array $streams = [];

    /** @var array<int, int> Last-activity timestamp for idle-timeout enforcement. */
    protected array $lastActivity = [];

    protected ?Socket $server = null;

    /** @var callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string */
    protected mixed $onMessage;

    /** @var list<callable(int $workerId): void> */
    protected array $onWorkerStartCallbacks = [];

    /**
     * @param string $host Host to bind to
     * @param int $port Port to listen on
     * @param int $maxClients Maximum concurrent TCP clients
     * @param int $idleTimeout Seconds before idle TCP connections are closed (RFC 7766)
     */
    public function __construct(
        protected string $host = '0.0.0.0',
        protected int $port = 8053,
        protected int $maxClients = 100,
        protected int $idleTimeout = 30,
    ) {
        $socket = \socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if (!$socket) {
            throw new Exception('Could not create TCP socket.');
        }

        socket_set_option($socket, SOL_SOCKET, SO_REUSEADDR, 1);
        $this->server = $socket;
    }

    public function onWorkerStart(callable $callback): void
    {
        $this->onWorkerStartCallbacks[] = $callback;
    }

    public function onMessage(callable $callback): void
    {
        $this->onMessage = $callback;
    }

    public function start(): void
    {
        if ($this->server === null) {
            throw new Exception('TCP server socket is not available.');
        }

        if (socket_bind($this->server, $this->host, $this->port) === false) {
            throw new Exception('Could not bind TCP server.');
        }

        if (socket_listen($this->server, 128) === false) {
            throw new Exception('Could not listen on TCP server.');
        }

        socket_set_nonblock($this->server);

        foreach ($this->onWorkerStartCallbacks as $callback) {
            \call_user_func($callback, 0);
        }

        /** @phpstan-ignore-next-line */
        while (1) {
            $this->closeIdleClients();

            $readSockets = [$this->server];
            foreach ($this->clients as $client) {
                $readSockets[] = $client;
            }

            $write = [];
            $except = [];

            // 1s timeout keeps the idle sweep responsive.
            $changed = socket_select($readSockets, $write, $except, 1);
            if ($changed === false || $changed === 0) {
                continue;
            }

            foreach ($readSockets as $sock) {
                if ($sock === $this->server) {
                    $this->acceptClient();
                    continue;
                }

                $this->readClient($sock);
            }
        }
    }

    public function getName(): string
    {
        return 'native-tcp';
    }

    public function getServerSocket(): ?Socket
    {
        return $this->server;
    }

    /**
     * @return list<Socket>
     */
    public function getClientSockets(): array
    {
        return array_values($this->clients);
    }

    protected function acceptClient(): void
    {
        if ($this->server === null) {
            return;
        }

        $client = @socket_accept($this->server);

        if (!$client instanceof Socket) {
            return;
        }

        if (count($this->clients) >= $this->maxClients) {
            @socket_close($client);
            return;
        }

        if (@socket_set_nonblock($client) === false) {
            @socket_close($client);
            return;
        }

        socket_set_option($client, SOL_SOCKET, SO_KEEPALIVE, 1);
        socket_set_option($client, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
        socket_set_option($client, SOL_SOCKET, SO_SNDTIMEO, ['sec' => 5, 'usec' => 0]);

        $peerIp = '';
        $peerPort = 0;
        socket_getpeername($client, $peerIp, $peerPort);

        $fd = spl_object_id($client);
        $this->clients[$fd] = $client;
        $this->lastActivity[$fd] = time();
        $this->streams[$fd] = new TcpMessageStream(
            peerIp: is_string($peerIp) ? $peerIp : '',
            peerPort: is_int($peerPort) ? $peerPort : 0,
            enableProxyProtocol: $this->enableProxyProtocol,
        );
    }

    public function readClient(Socket $client): void
    {
        $fd = spl_object_id($client);

        $chunk = @socket_read($client, 8192, PHP_BINARY_READ);

        if ($chunk === '' || $chunk === false) {
            $error = socket_last_error($client);

            if ($chunk === '' || !in_array($error, [SOCKET_EAGAIN, SOCKET_EWOULDBLOCK], true)) {
                $this->closeClient($client);
            }

            return;
        }

        $this->lastActivity[$fd] = time();

        $stream = $this->streams[$fd] ?? null;
        if ($stream === null) {
            $this->closeClient($client);
            return;
        }

        try {
            foreach ($stream->feed($chunk) as [$message, $ip, $port]) {
                $response = \call_user_func($this->onMessage, $message, $ip, $port, TcpMessageStream::MAX_MESSAGE_SIZE);

                if ($response !== '') {
                    $this->writeFramed($client, $response);
                }
            }
        } catch (ProxyDecodingException | MessageDecodingException) {
            $this->closeClient($client);
        }
    }

    protected function writeFramed(Socket $client, string $response): void
    {
        $length = strlen($response);

        if ($length > TcpMessageStream::MAX_MESSAGE_SIZE) {
            // Truncation should have been applied upstream; oversize payloads
            // would silently corrupt framing via the 2-byte length prefix.
            $this->closeClient($client);
            return;
        }

        $frame = pack('n', $length) . $response;
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

                $this->closeClient($client);
                return;
            }

            $sent += $written;
        }
    }

    /**
     * Close idle TCP connections per RFC 7766 § 6.2.3.
     */
    protected function closeIdleClients(): void
    {
        $now = time();

        foreach ($this->clients as $fd => $client) {
            $last = $this->lastActivity[$fd] ?? 0;

            if (($now - $last) > $this->idleTimeout) {
                $this->closeClient($client);
            }
        }
    }

    protected function closeClient(Socket $client): void
    {
        $fd = spl_object_id($client);

        if (!isset($this->clients[$fd])) {
            return;
        }

        unset($this->clients[$fd], $this->lastActivity[$fd], $this->streams[$fd]);

        @socket_close($client);
    }
}
