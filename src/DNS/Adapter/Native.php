<?php

namespace Utopia\DNS\Adapter;

use Exception;
use Socket;
use Utopia\DNS\Adapter;

class Native extends Adapter
{
    protected Socket $udpServer;

    protected ?Socket $tcpServer = null;

    /** @var array<int, Socket> Active TCP client sockets, keyed by fd id. */
    protected array $tcpClients = [];

    /** @var array<int, int> Last activity timestamp per TCP client for idle timeout. */
    protected array $tcpLastActivity = [];

    /** @var callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string */
    protected mixed $onUdpPacket;

    /** @var callable(int $fd, string $bytes, string $ip, int $port): void */
    protected mixed $onTcpReceive;

    /** @var callable(int $fd): void */
    protected mixed $onTcpClose;

    /** @var list<callable(int $workerId): void> */
    protected array $onWorkerStartCallbacks = [];

    /**
     * @param string $host Host to bind to
     * @param int $port Port to listen on
     * @param bool $enableTcp Enable TCP support (RFC 5966)
     * @param int $maxTcpClients Maximum concurrent TCP clients
     * @param int $tcpIdleTimeout Seconds before idle TCP connections are closed (RFC 7766)
     */
    public function __construct(
        protected string $host = '0.0.0.0',
        protected int $port = 8053,
        protected bool $enableTcp = true,
        protected int $maxTcpClients = 100,
        protected int $tcpIdleTimeout = 30,
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

    public function onWorkerStart(callable $callback): void
    {
        $this->onWorkerStartCallbacks[] = $callback;
    }

    public function onUdpPacket(callable $callback): void
    {
        $this->onUdpPacket = $callback;
    }

    public function onTcpReceive(callable $callback): void
    {
        $this->onTcpReceive = $callback;
    }

    public function onTcpClose(callable $callback): void
    {
        $this->onTcpClose = $callback;
    }

    public function sendTcp(int $fd, string $data): void
    {
        $client = $this->tcpClients[$fd] ?? null;
        if ($client === null) {
            return;
        }

        $total = strlen($data);
        $sent = 0;

        while ($sent < $total) {
            $written = @socket_write($client, substr($data, $sent));

            if ($written === false) {
                $error = socket_last_error($client);

                if (in_array($error, [SOCKET_EAGAIN, SOCKET_EWOULDBLOCK], true)) {
                    socket_clear_error($client);
                    usleep(1000);
                    continue;
                }

                $this->closeTcpInternal($client);
                return;
            }

            $sent += $written;
        }
    }

    public function closeTcp(int $fd): void
    {
        $client = $this->tcpClients[$fd] ?? null;
        if ($client !== null) {
            $this->closeTcpInternal($client);
        }
    }

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

        foreach ($this->onWorkerStartCallbacks as $callback) {
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

            $changed = socket_select($readSockets, $write, $except, 1);

            if ($changed === false || $changed === 0) {
                continue;
            }

            foreach ($readSockets as $socket) {
                if ($socket === $this->udpServer) {
                    $this->handleUdp();
                    continue;
                }

                if ($this->tcpServer !== null && $socket === $this->tcpServer) {
                    $this->acceptTcp();
                    continue;
                }

                $this->readTcp($socket);
            }
        }
    }

    public function getName(): string
    {
        return 'native';
    }

    protected function handleUdp(): void
    {
        $buf = '';
        $ip = '';
        $port = 0;
        $len = socket_recvfrom($this->udpServer, $buf, 1024 * 4, 0, $ip, $port);

        if ($len === false || $len <= 0 || !is_string($buf) || !is_string($ip) || !is_int($port)) {
            return;
        }

        $response = \call_user_func($this->onUdpPacket, $buf, $ip, $port, 512);

        if ($response !== '') {
            socket_sendto($this->udpServer, $response, strlen($response), 0, $ip, $port);
        }
    }

    protected function acceptTcp(): void
    {
        if ($this->tcpServer === null) {
            return;
        }

        $client = @socket_accept($this->tcpServer);

        if (!$client instanceof Socket) {
            return;
        }

        if (count($this->tcpClients) >= $this->maxTcpClients) {
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

        $fd = spl_object_id($client);
        $this->tcpClients[$fd] = $client;
        $this->tcpLastActivity[$fd] = time();
    }

    protected function readTcp(Socket $client): void
    {
        $fd = spl_object_id($client);

        $chunk = @socket_read($client, 8192, PHP_BINARY_READ);

        if ($chunk === '' || $chunk === false) {
            $error = socket_last_error($client);

            if ($chunk === '' || !in_array($error, [SOCKET_EAGAIN, SOCKET_EWOULDBLOCK], true)) {
                $this->closeTcpInternal($client);
            }

            return;
        }

        $this->tcpLastActivity[$fd] = time();

        $ip = '';
        $port = 0;
        socket_getpeername($client, $ip, $port);

        \call_user_func(
            $this->onTcpReceive,
            $fd,
            $chunk,
            is_string($ip) ? $ip : '',
            is_int($port) ? $port : 0,
        );
    }

    /**
     * Close idle TCP connections per RFC 7766 Section 6.2.3.
     */
    protected function closeIdleTcpClients(): void
    {
        $now = time();

        foreach ($this->tcpClients as $fd => $client) {
            $lastActivity = $this->tcpLastActivity[$fd] ?? 0;

            if (($now - $lastActivity) > $this->tcpIdleTimeout) {
                $this->closeTcpInternal($client);
            }
        }
    }

    protected function closeTcpInternal(Socket $client): void
    {
        $fd = spl_object_id($client);

        if (!isset($this->tcpClients[$fd])) {
            return;
        }

        unset($this->tcpClients[$fd], $this->tcpLastActivity[$fd]);

        @socket_close($client);

        \call_user_func($this->onTcpClose, $fd);
    }
}
