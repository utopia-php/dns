<?php

namespace Utopia\DNS;

use Utopia\DNS\Exception\ProxyProtocol\DecodingException;

/**
 * Stateful PROXY protocol preamble resolver for a single TCP connection.
 *
 * Wraps the stateless {@see ProxyProtocol} decoder with enough state to know
 * whether the preamble has already been consumed on this connection, so that
 * bytes after the preamble flow through without re-parsing.
 *
 * TCP adapters create one instance per accepted connection and feed bytes
 * via {@see resolve()} until it reports a definitive state.
 *
 * UDP adapters use the stateless {@see unwrapDatagram()} helper: each
 * datagram is self-contained, so no per-peer state is needed.
 */
final class ProxyProtocolStream
{
    public const int STATE_UNRESOLVED = 0;

    public const int STATE_DIRECT = 1;

    public const int STATE_PROXIED = 2;

    private int $state = self::STATE_UNRESOLVED;

    private ?ProxyProtocol $header = null;

    /**
     * Attempt to resolve the PROXY preamble from the start of the buffer.
     *
     * On successful resolution, the preamble bytes are stripped from
     * $buffer by reference and the state transitions to PROXIED (with the
     * parsed header retrievable via {@see header()}). If the buffer is
     * definitely not a PROXY preamble, the state transitions to DIRECT and
     * $buffer is left untouched. If the buffer could still be a valid
     * preamble but is incomplete, the state stays UNRESOLVED — callers
     * should accumulate more bytes and call again.
     *
     * Calls after resolution are no-ops and return the cached state.
     *
     * @throws DecodingException when the buffer starts with a PROXY
     *                           signature but the preamble is malformed.
     */
    public function resolve(string &$buffer): int
    {
        if ($this->state !== self::STATE_UNRESOLVED) {
            return $this->state;
        }

        $version = ProxyProtocol::detect($buffer);

        if ($version === null) {
            return self::STATE_UNRESOLVED;
        }

        if ($version === 0) {
            $this->state = self::STATE_DIRECT;
            return $this->state;
        }

        $header = ProxyProtocol::decode($buffer);

        if ($header === null) {
            return self::STATE_UNRESOLVED;
        }

        $this->header = $header;
        $buffer = \substr($buffer, $header->bytesConsumed);
        $this->state = self::STATE_PROXIED;

        return $this->state;
    }

    public function state(): int
    {
        return $this->state;
    }

    public function header(): ?ProxyProtocol
    {
        return $this->header;
    }

    public function isResolved(): bool
    {
        return $this->state !== self::STATE_UNRESOLVED;
    }

    public function isProxied(): bool
    {
        return $this->state === self::STATE_PROXIED;
    }

    /**
     * Strip a PROXY preamble from a single UDP datagram.
     *
     * Returns the parsed header when a preamble was present and consumed
     * (the buffer is stripped in place). Returns null when the datagram
     * does not start with a PROXY signature — callers should treat it as a
     * direct datagram. Throws when the datagram starts with a signature
     * but the preamble is malformed or incomplete; callers should drop the
     * datagram in that case (unlike TCP, UDP has no "wait for more").
     *
     * @throws DecodingException
     */
    public static function unwrapDatagram(string &$buffer): ?ProxyProtocol
    {
        $version = ProxyProtocol::detect($buffer);

        if ($version === 0) {
            return null;
        }

        if ($version === null) {
            throw new DecodingException('PROXY datagram is too short to classify.');
        }

        $header = ProxyProtocol::decode($buffer);

        if ($header === null) {
            throw new DecodingException('PROXY datagram preamble is incomplete.');
        }

        $buffer = \substr($buffer, $header->bytesConsumed);

        return $header;
    }
}
