<?php

namespace Utopia\DNS\Adapter;

use Exception;
use Socket;
use Utopia\DNS\Adapter;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException as ProxyDecodingException;
use Utopia\DNS\ProxyProtocolStream;

/**
 * UDP-only DNS adapter built on PHP's `ext-sockets`.
 *
 * Receives datagrams, optionally strips a PROXY protocol preamble to
 * recover the real client address, and delegates handling to the
 * registered {@see Adapter::onMessage()} callback.
 *
 * Replies are sent back to the transport peer (i.e. the proxy, if any) —
 * not to the PROXY-declared source — because the return path must
 * follow the network path of the request.
 */
class NativeUdp extends Adapter
{
    /** RFC 1035: unicast UDP DNS messages are capped at 512 bytes. */
    public const int UDP_MAX_MESSAGE_SIZE = 512;

    protected Socket $socket;

    /** @var callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string */
    protected mixed $onMessage;

    /** @var list<callable(int $workerId): void> */
    protected array $onWorkerStartCallbacks = [];

    public function __construct(
        protected string $host = '0.0.0.0',
        protected int $port = 8053,
    ) {
        $socket = \socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if (!$socket) {
            throw new Exception('Could not create UDP socket.');
        }
        $this->socket = $socket;
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
        if (socket_bind($this->socket, $this->host, $this->port) === false) {
            throw new Exception('Could not bind UDP server.');
        }

        foreach ($this->onWorkerStartCallbacks as $callback) {
            \call_user_func($callback, 0);
        }

        /** @phpstan-ignore-next-line */
        while (1) {
            $readSockets = [$this->socket];
            $write = [];
            $except = [];

            $changed = socket_select($readSockets, $write, $except, null);
            if ($changed === false || $changed === 0) {
                continue;
            }

            $this->handleReadable();
        }
    }

    public function getName(): string
    {
        return 'native-udp';
    }

    /**
     * Non-blocking single iteration — useful for composite adapters that
     * run their own select loop over the sockets exposed via
     * {@see getSocket()}.
     */
    public function handleReadable(): void
    {
        $buf = '';
        $ip = '';
        $port = 0;
        $len = socket_recvfrom($this->socket, $buf, 1024 * 4, 0, $ip, $port);

        if ($len === false || $len <= 0 || !is_string($buf) || !is_string($ip) || !is_int($port)) {
            return;
        }

        // Reply goes back to the actual UDP peer, not the PROXY-declared source.
        $replyIp = $ip;
        $replyPort = $port;

        if ($this->enableProxyProtocol) {
            try {
                $header = ProxyProtocolStream::unwrapDatagram($buf);
            } catch (ProxyDecodingException) {
                return;
            }

            if ($header !== null && $header->sourceAddress !== null && $header->sourcePort !== null) {
                $ip = $header->sourceAddress;
                $port = $header->sourcePort;
            }
        }

        $response = \call_user_func($this->onMessage, $buf, $ip, $port, self::UDP_MAX_MESSAGE_SIZE);

        if ($response !== '') {
            socket_sendto($this->socket, $response, strlen($response), 0, $replyIp, $replyPort);
        }
    }

    public function getSocket(): Socket
    {
        return $this->socket;
    }
}
