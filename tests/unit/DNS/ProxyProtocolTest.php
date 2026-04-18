<?php

namespace Tests\Unit\Utopia\DNS;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException;
use Utopia\DNS\ProxyProtocol;
use Utopia\DNS\ProxyProtocolHeader;

final class ProxyProtocolTest extends TestCase
{
    public function testDetectV1(): void
    {
        $this->assertSame(1, ProxyProtocol::detect("PROXY TCP4 1.2.3.4 5.6.7.8 1111 2222\r\n"));
    }

    public function testDetectV2(): void
    {
        $this->assertSame(2, ProxyProtocol::detect(ProxyProtocol::V2_SIGNATURE . "\x21\x11\x00\x0C"));
    }

    public function testDetectPartialV1ReturnsNull(): void
    {
        $this->assertNull(ProxyProtocol::detect('PROX'));
    }

    public function testDetectPartialV2ReturnsNull(): void
    {
        $this->assertNull(ProxyProtocol::detect("\r\n\r\n\x00"));
    }

    public function testDetectNonProxy(): void
    {
        $this->assertSame(0, ProxyProtocol::detect("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"));
    }

    public function testParseV1Tcp4(): void
    {
        $header = "PROXY TCP4 192.168.1.1 10.0.0.1 56324 443\r\n";
        $result = ProxyProtocol::parse($header);

        $this->assertInstanceOf(ProxyProtocolHeader::class, $result);
        $this->assertSame(1, $result->version);
        $this->assertFalse($result->isLocal);
        $this->assertSame(ProxyProtocolHeader::FAMILY_TCP4, $result->family);
        $this->assertSame('192.168.1.1', $result->sourceAddress);
        $this->assertSame('10.0.0.1', $result->destinationAddress);
        $this->assertSame(56324, $result->sourcePort);
        $this->assertSame(443, $result->destinationPort);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testParseV1Tcp6(): void
    {
        $header = "PROXY TCP6 2001:db8::1 2001:db8::2 65535 53\r\n";
        $result = ProxyProtocol::parse($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocolHeader::FAMILY_TCP6, $result->family);
        $this->assertSame('2001:db8::1', $result->sourceAddress);
        $this->assertSame('2001:db8::2', $result->destinationAddress);
        $this->assertSame(65535, $result->sourcePort);
        $this->assertSame(53, $result->destinationPort);
    }

    public function testParseV1Unknown(): void
    {
        $header = "PROXY UNKNOWN\r\n";
        $result = ProxyProtocol::parse($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocolHeader::FAMILY_UNKNOWN, $result->family);
        $this->assertNull($result->sourceAddress);
        $this->assertNull($result->destinationAddress);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testParseV1UnknownWithExtraTokensIgnored(): void
    {
        // Per spec, receivers must ignore everything past UNKNOWN on the line.
        $header = "PROXY UNKNOWN ff:ff::1 aa:aa::2 1234 5678\r\n";
        $result = ProxyProtocol::parse($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocolHeader::FAMILY_UNKNOWN, $result->family);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testParseV1ReturnsNullWhenCrlfMissing(): void
    {
        $this->assertNull(ProxyProtocol::parse('PROXY TCP4 1.2.3.4 5.6.7.8 1 2'));
    }

    public function testParseV1ThrowsWhenTooLong(): void
    {
        $this->expectException(DecodingException::class);
        ProxyProtocol::parse('PROXY TCP4 ' . str_repeat('a', 120));
    }

    public function testParseV1InvalidAddressThrows(): void
    {
        $this->expectException(DecodingException::class);
        ProxyProtocol::parse("PROXY TCP4 999.999.999.999 10.0.0.1 1 2\r\n");
    }

    public function testParseV1InvalidPortThrows(): void
    {
        $this->expectException(DecodingException::class);
        ProxyProtocol::parse("PROXY TCP4 1.2.3.4 5.6.7.8 70000 80\r\n");
    }

    public function testParseV1Ipv4ForTcp6Mismatch(): void
    {
        $this->expectException(DecodingException::class);
        ProxyProtocol::parse("PROXY TCP6 1.2.3.4 5.6.7.8 1 2\r\n");
    }

    public function testParseV2Inet4(): void
    {
        $payload = inet_pton('192.168.1.1') . inet_pton('10.0.0.1') . pack('nn', 56324, 443);
        $header = ProxyProtocol::V2_SIGNATURE . chr(0x21) . chr(0x11) . pack('n', strlen($payload)) . $payload;

        $result = ProxyProtocol::parse($header);

        $this->assertNotNull($result);
        $this->assertSame(2, $result->version);
        $this->assertSame(ProxyProtocolHeader::FAMILY_TCP4, $result->family);
        $this->assertSame('192.168.1.1', $result->sourceAddress);
        $this->assertSame('10.0.0.1', $result->destinationAddress);
        $this->assertSame(56324, $result->sourcePort);
        $this->assertSame(443, $result->destinationPort);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testParseV2Inet6Udp(): void
    {
        $payload = inet_pton('2001:db8::1') . inet_pton('2001:db8::2') . pack('nn', 53, 5353);
        $header = ProxyProtocol::V2_SIGNATURE . chr(0x21) . chr(0x22) . pack('n', strlen($payload)) . $payload;

        $result = ProxyProtocol::parse($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocolHeader::FAMILY_UDP6, $result->family);
        $this->assertSame('2001:db8::1', $result->sourceAddress);
        $this->assertSame('2001:db8::2', $result->destinationAddress);
    }

    public function testParseV2Local(): void
    {
        // LOCAL command (0x20): no address, but still has a payload length field we must respect
        $payload = str_repeat("\x00", 12);
        $header = ProxyProtocol::V2_SIGNATURE . chr(0x20) . chr(0x00) . pack('n', strlen($payload)) . $payload;

        $result = ProxyProtocol::parse($header);

        $this->assertNotNull($result);
        $this->assertTrue($result->isLocal);
        $this->assertNull($result->sourceAddress);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testParseV2Unix(): void
    {
        $srcPath = str_pad('/var/run/src.sock', 108, "\x00");
        $dstPath = str_pad('/var/run/dst.sock', 108, "\x00");
        $payload = $srcPath . $dstPath;
        $header = ProxyProtocol::V2_SIGNATURE . chr(0x21) . chr(0x31) . pack('n', strlen($payload)) . $payload;

        $result = ProxyProtocol::parse($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocolHeader::FAMILY_UNIX, $result->family);
        $this->assertSame('/var/run/src.sock', $result->sourceAddress);
        $this->assertSame('/var/run/dst.sock', $result->destinationAddress);
    }

    public function testParseV2WithTlvSuffixIsConsumedByLength(): void
    {
        // Emulate a TLV appended to the addresses. Parser should skip past it
        // via the payload length so bytesConsumed covers the TLV too.
        $addrPayload = inet_pton('192.168.1.1') . inet_pton('10.0.0.1') . pack('nn', 1, 2);
        $tlv = "\x03\x00\x04ABCD"; // type=3, len=4, value=ABCD
        $payload = $addrPayload . $tlv;
        $header = ProxyProtocol::V2_SIGNATURE . chr(0x21) . chr(0x11) . pack('n', strlen($payload)) . $payload;

        $result = ProxyProtocol::parse($header);

        $this->assertNotNull($result);
        $this->assertSame('192.168.1.1', $result->sourceAddress);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testParseV2ReturnsNullWhenPayloadIncomplete(): void
    {
        $payload = inet_pton('192.168.1.1') . inet_pton('10.0.0.1') . pack('nn', 1, 2);
        $full = ProxyProtocol::V2_SIGNATURE . chr(0x21) . chr(0x11) . pack('n', strlen($payload)) . $payload;
        $truncated = substr($full, 0, strlen($full) - 4);

        $this->assertNull(ProxyProtocol::parse($truncated));
    }

    public function testParseV2InvalidVersionThrows(): void
    {
        $header = ProxyProtocol::V2_SIGNATURE . chr(0x31) . chr(0x11) . pack('n', 0);
        $this->expectException(DecodingException::class);
        ProxyProtocol::parse($header);
    }

    public function testParseNonProxyThrows(): void
    {
        $this->expectException(DecodingException::class);
        ProxyProtocol::parse("HELLO WORLD\r\n");
    }

    public function testDetectRejectsDnsPacketStartingWithNonPrefixByte(): void
    {
        // Typical DNS query header: ID 0x1234, flags 0x0100, 1 question, 0 answers...
        $dnsPacket = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        $this->assertSame(0, ProxyProtocol::detect($dnsPacket));
    }

    public function testDetectRejectsDnsPacketStartingWithCrButNotV2(): void
    {
        // Crafted: starts with 0x0D (same as v2 sig first byte) but second byte differs.
        $this->assertSame(0, ProxyProtocol::detect("\x0D\xFF\x00\x01"));
    }

    public function testDetectPartialSingleByteOfV1(): void
    {
        $this->assertNull(ProxyProtocol::detect('P'));
    }

    public function testDetectFullV1Prefix(): void
    {
        // Exactly "PROXY " with no trailing data is a prefix match, not a full line yet.
        $this->assertSame(1, ProxyProtocol::detect('PROXY '));
    }
}
