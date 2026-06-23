<?php

namespace Tests\Unit\Utopia\DNS;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException;
use Utopia\DNS\ProxyProtocol;
use Utopia\DNS\ProxyProtocolStream;

final class ProxyProtocolStreamTest extends TestCase
{
    // ---------------------------------------------------------------------
    // resolve() (stateful TCP use)
    // ---------------------------------------------------------------------

    public function testNewStreamIsUnresolved(): void
    {
        $stream = new ProxyProtocolStream();

        $this->assertFalse($stream->isResolved());
        $this->assertFalse($stream->isProxied());
        $this->assertNull($stream->header());
        $this->assertSame(ProxyProtocolStream::STATE_UNRESOLVED, $stream->state());
    }

    public function testResolveWithDnsLikeBufferTransitionsToDirect(): void
    {
        $stream = new ProxyProtocolStream();
        $buffer = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        $original = $buffer;

        $state = $stream->resolve($buffer);

        $this->assertSame(ProxyProtocolStream::STATE_DIRECT, $state);
        $this->assertTrue($stream->isResolved());
        $this->assertFalse($stream->isProxied());
        $this->assertNull($stream->header());
        $this->assertSame($original, $buffer, 'DIRECT state must not modify buffer');
    }

    public function testResolveWithCompleteV1PreambleConsumesAndResolves(): void
    {
        $stream = new ProxyProtocolStream();
        $preamble = "PROXY TCP4 1.2.3.4 5.6.7.8 111 222\r\n";
        $payload = "\x00\x0aHELLODNS!";
        $buffer = $preamble . $payload;

        $state = $stream->resolve($buffer);

        $this->assertSame(ProxyProtocolStream::STATE_PROXIED, $state);
        $this->assertTrue($stream->isResolved());
        $this->assertTrue($stream->isProxied());
        $this->assertSame($payload, $buffer, 'preamble bytes should be stripped from buffer');

        $header = $stream->header();
        $this->assertNotNull($header);
        $this->assertSame('1.2.3.4', $header->sourceAddress);
        $this->assertSame(111, $header->sourcePort);
    }

    public function testResolveWithCompleteV2PreambleConsumesAndResolves(): void
    {
        $stream = new ProxyProtocolStream();
        $addrPayload = inet_pton('10.0.0.1') . inet_pton('10.0.0.2') . pack('nn', 5000, 53);
        $preamble = ProxyProtocol::V2_SIGNATURE
            . chr(0x21)
            . chr(0x11)
            . pack('n', strlen($addrPayload))
            . $addrPayload;
        $payload = "REMAINING";
        $buffer = $preamble . $payload;

        $state = $stream->resolve($buffer);

        $this->assertSame(ProxyProtocolStream::STATE_PROXIED, $state);
        $this->assertSame($payload, $buffer);
        $this->assertNotNull($stream->header());
        $this->assertSame('10.0.0.1', $stream->header()->sourceAddress);
    }

    public function testResolveWithPartialPreambleStaysUnresolved(): void
    {
        $stream = new ProxyProtocolStream();
        $buffer = 'PROXY TCP4 1.2.3.4 5.6.7.8';

        $state = $stream->resolve($buffer);

        $this->assertSame(ProxyProtocolStream::STATE_UNRESOLVED, $state);
        $this->assertFalse($stream->isResolved());
        $this->assertSame('PROXY TCP4 1.2.3.4 5.6.7.8', $buffer, 'unresolved must not modify buffer');
    }

    public function testResolveIsIdempotentAfterDirectResolution(): void
    {
        $stream = new ProxyProtocolStream();
        $buffer = "\x00\x01\x00\x00";
        $stream->resolve($buffer);

        // Subsequent calls with different buffers should return the cached state.
        $newBuffer = 'anything';
        $state = $stream->resolve($newBuffer);
        $this->assertSame(ProxyProtocolStream::STATE_DIRECT, $state);
        $this->assertSame('anything', $newBuffer);
    }

    public function testResolveIsIdempotentAfterProxiedResolution(): void
    {
        $stream = new ProxyProtocolStream();
        $buffer = "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\nHELLO";
        $stream->resolve($buffer);
        $this->assertSame('HELLO', $buffer);

        // A second call must not strip more bytes.
        $state = $stream->resolve($buffer);
        $this->assertSame(ProxyProtocolStream::STATE_PROXIED, $state);
        $this->assertSame('HELLO', $buffer);
    }

    public function testResolveChunkedV1AcrossManyCalls(): void
    {
        $full = "PROXY TCP4 192.168.1.1 10.0.0.1 56324 443\r\n";
        $trailing = "\x00\x04TAIL";

        $stream = new ProxyProtocolStream();
        $buffer = '';

        for ($i = 0; $i < strlen($full) - 1; $i++) {
            $buffer .= $full[$i];
            $this->assertSame(
                ProxyProtocolStream::STATE_UNRESOLVED,
                $stream->resolve($buffer),
                "Expected unresolved at byte {$i}"
            );
        }

        // Deliver the last preamble byte plus the trailing data in one chunk.
        $buffer .= $full[strlen($full) - 1] . $trailing;
        $state = $stream->resolve($buffer);

        $this->assertSame(ProxyProtocolStream::STATE_PROXIED, $state);
        $this->assertSame($trailing, $buffer);
        $this->assertSame('192.168.1.1', $stream->header()?->sourceAddress);
    }

    public function testResolveChunkedV2AcrossManyCalls(): void
    {
        $payload = inet_pton('1.2.3.4') . inet_pton('5.6.7.8') . pack('nn', 1, 2);
        $full = ProxyProtocol::V2_SIGNATURE
            . chr(0x21)
            . chr(0x11)
            . pack('n', strlen($payload))
            . $payload;

        $stream = new ProxyProtocolStream();
        $buffer = '';

        for ($i = 0; $i < strlen($full) - 1; $i++) {
            $buffer .= $full[$i];
            $this->assertSame(
                ProxyProtocolStream::STATE_UNRESOLVED,
                $stream->resolve($buffer),
                "Expected unresolved at byte {$i}"
            );
        }

        $buffer .= $full[strlen($full) - 1];
        $this->assertSame(ProxyProtocolStream::STATE_PROXIED, $stream->resolve($buffer));
        $this->assertSame('', $buffer);
    }

    public function testResolveThrowsOnMalformedPreamble(): void
    {
        $stream = new ProxyProtocolStream();
        $buffer = "PROXY TCP4 not-an-ip 5.6.7.8 1 2\r\n";

        $this->expectException(DecodingException::class);
        $stream->resolve($buffer);
    }

    public function testResolveThrowOnMalformedLeavesStreamUnresolved(): void
    {
        $stream = new ProxyProtocolStream();
        $buffer = "PROXY TCP4 not-an-ip 5.6.7.8 1 2\r\n";

        try {
            $stream->resolve($buffer);
            $this->fail('Expected DecodingException');
        } catch (DecodingException) {
            // Expected.
        }

        // Stream stays unresolved so callers can close the connection.
        $this->assertFalse($stream->isResolved());
    }

    // ---------------------------------------------------------------------
    // unwrapDatagram() (stateless UDP use)
    // ---------------------------------------------------------------------

    public function testUnwrapDatagramReturnsNullForDirectDns(): void
    {
        $buffer = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        $original = $buffer;

        $header = ProxyProtocolStream::unwrapDatagram($buffer);

        $this->assertNull($header);
        $this->assertSame($original, $buffer, 'direct datagram must not be modified');
    }

    public function testUnwrapDatagramStripsCompleteV1Preamble(): void
    {
        $preamble = "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n";
        $payload = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        $buffer = $preamble . $payload;

        $header = ProxyProtocolStream::unwrapDatagram($buffer);

        $this->assertNotNull($header);
        $this->assertSame('1.2.3.4', $header->sourceAddress);
        $this->assertSame($payload, $buffer);
    }

    public function testUnwrapDatagramStripsCompleteV2Preamble(): void
    {
        $addrPayload = inet_pton('10.0.0.1') . inet_pton('10.0.0.2') . pack('nn', 53, 5353);
        $preamble = ProxyProtocol::V2_SIGNATURE
            . chr(0x21)
            . chr(0x12) // UDP4
            . pack('n', strlen($addrPayload))
            . $addrPayload;
        $payload = 'DNSDATA';
        $buffer = $preamble . $payload;

        $header = ProxyProtocolStream::unwrapDatagram($buffer);

        $this->assertNotNull($header);
        $this->assertSame(ProxyProtocol::FAMILY_UDP4, $header->family);
        $this->assertSame($payload, $buffer);
    }

    public function testUnwrapDatagramThrowsOnIncompleteDatagram(): void
    {
        // Datagram begins with 'P' but is too short to be a complete PROXY signature.
        $buffer = 'PRO';

        $this->expectException(DecodingException::class);
        ProxyProtocolStream::unwrapDatagram($buffer);
    }

    public function testUnwrapDatagramThrowsOnIncompleteV2Datagram(): void
    {
        // Datagram starts with v2 signature but payload is truncated.
        $addrPayload = inet_pton('1.2.3.4') . inet_pton('5.6.7.8') . pack('nn', 1, 2);
        $preamble = ProxyProtocol::V2_SIGNATURE
            . chr(0x21)
            . chr(0x11)
            . pack('n', strlen($addrPayload))
            . substr($addrPayload, 0, -2); // chop off part of the ports

        $this->expectException(DecodingException::class);
        ProxyProtocolStream::unwrapDatagram($preamble);
    }

    public function testUnwrapDatagramThrowsOnMalformedPreamble(): void
    {
        $buffer = "PROXY TCP4 not-an-ip 5.6.7.8 1 2\r\nDNSDATA";

        $this->expectException(DecodingException::class);
        ProxyProtocolStream::unwrapDatagram($buffer);
    }
}
