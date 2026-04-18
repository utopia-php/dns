<?php

namespace Utopia\DNS;

use Generator;
use Utopia\DNS\Exception\Message\DecodingException as MessageDecodingException;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException as ProxyDecodingException;

/**
 * Per-connection TCP byte-stream → DNS messages pipeline.
 *
 * Encapsulates everything an adapter needs to turn raw TCP bytes into
 * complete DNS messages with a resolved peer address:
 *
 *   - Accumulates inbound bytes with an overall buffer cap.
 *   - Consumes a leading PROXY protocol preamble (v1 or v2) if enabled,
 *     overriding the peer address with the PROXY source.
 *   - Extracts RFC 1035 / 7766 length-prefixed DNS messages.
 *
 * Adapters feed bytes as they arrive and iterate over {@see feed()} to
 * receive ready messages plus the current peer address. Thrown
 * exceptions signal unrecoverable stream errors — callers should close
 * the connection.
 */
final class TcpMessageStream
{
    /** RFC 1035 Section 4.2.2: TCP frames use a 2-byte length prefix, max 65535 bytes. */
    public const int MAX_MESSAGE_SIZE = 65535;

    /**
     * Hard cap on per-connection buffer size. Must hold at least one
     * max-sized DNS frame plus a PROXY v1 preamble (107 bytes), with
     * headroom to prevent slow-loris style attacks.
     */
    public const int MAX_BUFFER_SIZE = 131072;

    private string $buffer = '';

    private ?ProxyProtocolStream $proxyStream;

    public function __construct(
        private string $peerIp,
        private int $peerPort,
        bool $enableProxyProtocol = false,
    ) {
        $this->proxyStream = $enableProxyProtocol ? new ProxyProtocolStream() : null;
    }

    /**
     * Feed newly-received bytes and iterate over any complete DNS
     * messages that are now available.
     *
     * Each yielded value is a tuple [message bytes, peer ip, peer port].
     * The peer fields reflect the current resolved address — for a
     * PROXY-enabled stream they switch from the transport peer to the
     * PROXY-declared source after the preamble is consumed.
     *
     * @return Generator<int, array{0: string, 1: string, 2: int}>
     *
     * @throws ProxyDecodingException   if the PROXY preamble is malformed.
     * @throws MessageDecodingException if framing is invalid or the buffer overflows.
     */
    public function feed(string $bytes): Generator
    {
        $this->buffer .= $bytes;

        if (\strlen($this->buffer) > self::MAX_BUFFER_SIZE) {
            throw new MessageDecodingException('TCP buffer exceeded maximum size.');
        }

        if ($this->proxyStream !== null && $this->proxyStream->state() === ProxyProtocolStream::STATE_UNRESOLVED) {
            $state = $this->proxyStream->resolve($this->buffer);

            if ($state === ProxyProtocolStream::STATE_UNRESOLVED) {
                return;
            }

            $header = $this->proxyStream->header();
            if ($header !== null && $header->sourceAddress !== null && $header->sourcePort !== null) {
                $this->peerIp = $header->sourceAddress;
                $this->peerPort = $header->sourcePort;
            }
        }

        while (\strlen($this->buffer) >= 2) {
            $unpacked = \unpack('n', \substr($this->buffer, 0, 2));
            $frameLength = (\is_array($unpacked) && \is_int($unpacked[1] ?? null)) ? $unpacked[1] : 0;

            if ($frameLength === 0) {
                throw new MessageDecodingException('TCP frame announced zero length.');
            }

            if ($frameLength > self::MAX_MESSAGE_SIZE) {
                throw new MessageDecodingException("TCP frame length {$frameLength} exceeds maximum.");
            }

            if (\strlen($this->buffer) < $frameLength + 2) {
                return;
            }

            $message = \substr($this->buffer, 2, $frameLength);
            $this->buffer = \substr($this->buffer, $frameLength + 2);

            yield [$message, $this->peerIp, $this->peerPort];
        }
    }

    public function peerIp(): string
    {
        return $this->peerIp;
    }

    public function peerPort(): int
    {
        return $this->peerPort;
    }
}
