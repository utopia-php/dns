<?php

namespace Utopia\DNS;

/**
 * Transport adapter contract.
 *
 * Adapters are responsible for the wire — receiving bytes from UDP
 * datagrams and TCP connections, and sending bytes back. All DNS-level
 * concerns (length-prefix framing, PROXY protocol, response generation)
 * live in {@see Server}.
 */
abstract class Adapter
{
    /**
     * Whether incoming traffic may be prefixed with a PROXY protocol
     * preamble. The adapter itself does not parse PROXY — this flag just
     * informs the adapter about how to configure its transport (e.g.
     * Swoole's kernel-level length-check framing is incompatible with a
     * PROXY preamble and must be disabled when this is true).
     */
    protected bool $enableProxyProtocol = false;

    public function setProxyProtocol(bool $enabled): void
    {
        $this->enableProxyProtocol = $enabled;
    }

    public function hasProxyProtocol(): bool
    {
        return $this->enableProxyProtocol;
    }

    /**
     * Worker start callback. Invoked once per worker.
     *
     * @param callable(int $workerId): void $callback
     * @phpstan-param callable(int $workerId): void $callback
     */
    abstract public function onWorkerStart(callable $callback): void;

    /**
     * Register the UDP datagram handler.
     *
     * The callback is invoked with the full datagram payload and the
     * transport peer's IP/port. It returns the bytes to send back, or an
     * empty string to send nothing.
     *
     * @param callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string $callback
     * @phpstan-param callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string $callback
     */
    abstract public function onUdpPacket(callable $callback): void;

    /**
     * Register the TCP receive handler.
     *
     * The callback is invoked with a connection identifier, a chunk of
     * freshly-received bytes, and the transport peer's IP/port. The chunk
     * may contain partial or multiple DNS messages; framing is the
     * handler's responsibility. Responses are sent via {@see sendTcp()},
     * not via a return value.
     *
     * @param callable(int $fd, string $bytes, string $ip, int $port): void $callback
     * @phpstan-param callable(int $fd, string $bytes, string $ip, int $port): void $callback
     */
    abstract public function onTcpReceive(callable $callback): void;

    /**
     * Register a TCP close handler so listeners can drop per-connection
     * state. Called once per connection identifier after the underlying
     * socket has been closed (by either end).
     *
     * @param callable(int $fd): void $callback
     * @phpstan-param callable(int $fd): void $callback
     */
    abstract public function onTcpClose(callable $callback): void;

    /**
     * Send bytes on a TCP connection identified by $fd. Silently no-ops if
     * the connection is no longer open.
     */
    abstract public function sendTcp(int $fd, string $data): void;

    /**
     * Forcefully close a TCP connection identified by $fd.
     */
    abstract public function closeTcp(int $fd): void;

    /**
     * Start the DNS server.
     */
    abstract public function start(): void;

    /**
     * Get the name of the adapter.
     */
    abstract public function getName(): string;
}
