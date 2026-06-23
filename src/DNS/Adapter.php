<?php

namespace Utopia\DNS;

/**
 * Transport adapter contract.
 *
 * Adapters own the wire — UDP sockets, TCP sockets, connection framing,
 * and PROXY protocol preamble handling. From the {@see Server}'s
 * perspective, DNS messages appear as generic "request with a client
 * address"; the adapter hides everything below.
 */
abstract class Adapter
{
    /**
     * Whether incoming traffic may be prefixed with a PROXY protocol
     * preamble. When enabled, the adapter strips the preamble (if
     * present) and reports the real client address through the
     * {@see onMessage()} callback.
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
     * Register the DNS message handler.
     *
     * Invoked once per complete DNS message, regardless of transport.
     * The adapter has already stripped any PROXY preamble and extracted
     * the framed message; $ip/$port reflect the real client address.
     *
     * The callback returns the response bytes to send back to the
     * client, or an empty string to suppress the response.
     *
     * $maxResponseSize is the maximum response size appropriate for the
     * transport (UDP: 512 per RFC 1035 unless EDNS0; TCP: 65535).
     *
     * @param callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string $callback
     * @phpstan-param callable(string $buffer, string $ip, int $port, ?int $maxResponseSize): string $callback
     */
    abstract public function onMessage(callable $callback): void;

    /**
     * Start the DNS server.
     */
    abstract public function start(): void;

    /**
     * Get the name of the adapter.
     */
    abstract public function getName(): string;
}
