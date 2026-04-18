<?php

namespace Utopia\DNS;

abstract class Adapter
{
    /**
     * Whether the adapter should treat incoming traffic as potentially
     * prefixed with a PROXY protocol (v1/v2) preamble. Configured via
     * {@see Server::setProxyProtocol()} (or directly via
     * {@see setProxyProtocol()}).
     */
    protected bool $enableProxyProtocol = false;

    /**
     * Toggle PROXY protocol awareness.
     *
     * Enabling this makes the adapter look for a PROXY preamble at the
     * start of every UDP datagram and TCP connection; traffic without a
     * preamble is still handled as direct DNS so health checks and direct
     * clients keep working.
     */
    public function setProxyProtocol(bool $enabled): void
    {
        $this->enableProxyProtocol = $enabled;
    }

    public function hasProxyProtocol(): bool
    {
        return $this->enableProxyProtocol;
    }

    /**
     * Worker start
     *
     * @param callable(int $workerId): void $callback
     * @phpstan-param callable(int $workerId): void $callback
     */
    abstract public function onWorkerStart(callable $callback): void;

    /**
     * Packet handler
     *
     * @param callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string $callback
     * @phpstan-param callable(string $buffer, string $ip, int $port, ?int $maxResponseSize):string $callback
     */
    abstract public function onPacket(callable $callback): void;

    /**
     * Start the DNS server
     */
    abstract public function start(): void;

    /**
     * Get the name of the adapter
     *
     * @return string
     */
    abstract public function getName(): string;
}
