<?php

namespace Utopia\DNS\Adapter;

use Exception;
use Socket;
use Utopia\DNS\Adapter;

class Native extends Adapter
{
    protected Socket $udpServer;

    protected ?Socket $tcpServer = null;

    /** @var array<int, Socket> */
    protected array $tcpClients = [];

    /** @var array<int, string> */
    protected array $tcpBuffers = [];

    /** @var callable(string $buffer, string $ip, int $port): string */
    protected mixed $onPacket;

    /** @var list<callable(int $workerId): void> */
    protected array $onWorkerStart = [];

    protected string $host;
    protected int $port;

    protected bool $enableTcp;

    /**
     * @param string $host
     * @param int $port
     */
    public function __construct(string $host = '0.0.0.0', int $port = 8053, bool $enableTcp = true)
    {
        $this->host = $host;
        $this->port = $port;
        $this->enableTcp = $enableTcp;

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
     * @phpstan-param callable(string $buffer, string $ip, int $port):string $callback
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
            $readSockets = [$this->udpServer];

            if ($this->tcpServer) {
                $readSockets[] = $this->tcpServer;
            }

            foreach ($this->tcpClients as $client) {
                $readSockets[] = $client;
            }

            $write = [];
            $except = [];

            $changed = socket_select($readSockets, $write, $except, null);

            if ($changed === false) {
                continue;
            }

            foreach ($readSockets as $socket) {
                if ($socket === $this->udpServer) {
                    $buf = '';
                    $ip = '';
                    $port = null;
                    $len = socket_recvfrom($this->udpServer, $buf, 1024 * 4, 0, $ip, $port);

                    if ($len > 0) {
                        $answer = call_user_func($this->onPacket, $buf, $ip, $port);

                        if ($answer === '') {
                            continue;
                        }

                        if (socket_sendto($this->udpServer, $answer, strlen($answer), 0, $ip, $port) === false) {
                            printf("Error sending UDP response\n");
                        }
                    }

                    continue;
                }

                if ($this->tcpServer !== null && $socket === $this->tcpServer) {
                    $client = @socket_accept($this->tcpServer);

                    if ($client instanceof Socket) {
                        socket_set_option($client, SOL_SOCKET, SO_KEEPALIVE, 1);
                        socket_set_option($client, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
                        socket_set_option($client, SOL_SOCKET, SO_SNDTIMEO, ['sec' => 5, 'usec' => 0]);

                        $id = spl_object_id($client);
                        $this->tcpClients[$id] = $client;
                        $this->tcpBuffers[$id] = '';
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

        $this->tcpBuffers[$clientId] = ($this->tcpBuffers[$clientId] ?? '') . $chunk;

        while (strlen($this->tcpBuffers[$clientId]) >= 2) {
            $length = unpack('nlen', substr($this->tcpBuffers[$clientId], 0, 2));
            $payloadLength = $length['len'] ?? 0;

            if ($payloadLength === 0) {
                $this->closeTcpClient($client);
                return;
            }

            if (strlen($this->tcpBuffers[$clientId]) < ($payloadLength + 2)) {
                return;
            }

            $message = substr($this->tcpBuffers[$clientId], 2, $payloadLength);
            $this->tcpBuffers[$clientId] = substr($this->tcpBuffers[$clientId], $payloadLength + 2);

            $ip = '';
            $port = 0;
            socket_getpeername($client, $ip, $port);

            $answer = call_user_func($this->onPacket, $message, $ip, $port);

            if ($answer === '') {
                continue;
            }

            $this->sendTcpResponse($client, $answer);
        }
    }

    protected function sendTcpResponse(Socket $client, string $payload): void
    {
        $frame = pack('n', strlen($payload)) . $payload;
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

    protected function closeTcpClient(Socket $client): void
    {
        $id = spl_object_id($client);

        unset($this->tcpClients[$id], $this->tcpBuffers[$id]);

        @socket_close($client);
    }
}
