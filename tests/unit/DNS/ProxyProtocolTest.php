<?php

namespace Tests\Unit\Utopia\DNS;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException;
use Utopia\DNS\ProxyProtocol;

final class ProxyProtocolTest extends TestCase
{
    // ---------------------------------------------------------------------
    // detect()
    // ---------------------------------------------------------------------

    public function testDetectEmptyBuffer(): void
    {
        $this->assertNull(ProxyProtocol::detect(''));
    }

    public function testDetectFullV1Match(): void
    {
        $this->assertSame(
            ProxyProtocol::VERSION_1,
            ProxyProtocol::detect("PROXY TCP4 1.2.3.4 5.6.7.8 1111 2222\r\n")
        );
    }

    public function testDetectFullV2Match(): void
    {
        $header = ProxyProtocol::V2_SIGNATURE . "\x21\x11\x00\x0C";
        $this->assertSame(ProxyProtocol::VERSION_2, ProxyProtocol::detect($header));
    }

    /** @return iterable<string, array{0: string}> */
    public static function partialV1Provider(): iterable
    {
        yield 'single P' => ['P'];
        yield 'two chars' => ['PR'];
        yield 'three chars' => ['PRO'];
        yield 'four chars' => ['PROX'];
        yield 'five chars' => ['PROXY'];
    }

    #[DataProvider('partialV1Provider')]
    public function testDetectPartialV1ReturnsNull(string $buffer): void
    {
        $this->assertNull(ProxyProtocol::detect($buffer));
    }

    /** @return iterable<string, array{0: string}> */
    public static function partialV2Provider(): iterable
    {
        for ($i = 1; $i < ProxyProtocol::V2_SIGNATURE_LENGTH; $i++) {
            yield "first {$i} bytes" => [substr(ProxyProtocol::V2_SIGNATURE, 0, $i)];
        }
    }

    #[DataProvider('partialV2Provider')]
    public function testDetectPartialV2ReturnsNull(string $buffer): void
    {
        $this->assertNull(ProxyProtocol::detect($buffer));
    }

    public function testDetectRejectsDnsQueryHeader(): void
    {
        // Standard DNS query: ID 0x1234, flags 0x0100, qd=1, everything else 0.
        $dnsPacket = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        $this->assertSame(0, ProxyProtocol::detect($dnsPacket));
    }

    public function testDetectRejectsCrPrefixButNotV2(): void
    {
        // Second byte differs from 0x0A.
        $this->assertSame(0, ProxyProtocol::detect("\r\xFF\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"));
    }

    public function testDetectRejectsPPrefixButNotV1(): void
    {
        // Starts with 'P' but not "PROXY ".
        $this->assertSame(0, ProxyProtocol::detect("PATH  /\r\n"));
    }

    public function testDetectRejectsNonPnonCrFirstByte(): void
    {
        $this->assertSame(0, ProxyProtocol::detect("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"));
    }

    /** @return iterable<string, array{0: int|null, 1: string}> */
    public static function detectBoundaryProvider(): iterable
    {
        yield 'v1 exact prefix' => [ProxyProtocol::VERSION_1, 'PROXY '];
        yield 'v1 prefix + CRLF' => [ProxyProtocol::VERSION_1, "PROXY \r\n"]; // Malformed body but prefix matches
        yield 'v2 exact signature' => [ProxyProtocol::VERSION_2, ProxyProtocol::V2_SIGNATURE];
        yield 'v2 signature + junk' => [ProxyProtocol::VERSION_2, ProxyProtocol::V2_SIGNATURE . "\x00\x00\x00\x00"];
    }

    #[DataProvider('detectBoundaryProvider')]
    public function testDetectBoundary(?int $expected, string $buffer): void
    {
        $this->assertSame($expected, ProxyProtocol::detect($buffer));
    }

    // ---------------------------------------------------------------------
    // decode() — v1
    // ---------------------------------------------------------------------

    public function testDecodeV1Tcp4(): void
    {
        $header = "PROXY TCP4 192.168.1.1 10.0.0.1 56324 443\r\n";
        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocol::VERSION_1, $result->version);
        $this->assertFalse($result->isLocal);
        $this->assertSame(ProxyProtocol::FAMILY_TCP4, $result->family);
        $this->assertSame('192.168.1.1', $result->sourceAddress);
        $this->assertSame('10.0.0.1', $result->destinationAddress);
        $this->assertSame(56324, $result->sourcePort);
        $this->assertSame(443, $result->destinationPort);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testDecodeV1Tcp6(): void
    {
        $header = "PROXY TCP6 2001:db8::1 2001:db8::2 65535 53\r\n";
        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocol::FAMILY_TCP6, $result->family);
        $this->assertSame('2001:db8::1', $result->sourceAddress);
        $this->assertSame('2001:db8::2', $result->destinationAddress);
        $this->assertSame(65535, $result->sourcePort);
        $this->assertSame(53, $result->destinationPort);
    }

    /** @return iterable<string, array{0: string, 1: int, 2: int}> */
    public static function v1PortBoundaryProvider(): iterable
    {
        yield 'zero src, zero dst' => ["PROXY TCP4 1.2.3.4 5.6.7.8 0 0\r\n", 0, 0];
        yield 'max src, min dst' => ["PROXY TCP4 1.2.3.4 5.6.7.8 65535 1\r\n", 65535, 1];
        yield 'min src, max dst' => ["PROXY TCP4 1.2.3.4 5.6.7.8 1 65535\r\n", 1, 65535];
        yield 'both middle' => ["PROXY TCP4 1.2.3.4 5.6.7.8 8080 8081\r\n", 8080, 8081];
    }

    #[DataProvider('v1PortBoundaryProvider')]
    public function testDecodeV1PortBoundaries(string $header, int $expectedSrc, int $expectedDst): void
    {
        $result = ProxyProtocol::decode($header);
        $this->assertNotNull($result);
        $this->assertSame($expectedSrc, $result->sourcePort);
        $this->assertSame($expectedDst, $result->destinationPort);
    }

    public function testDecodeV1Unknown(): void
    {
        $header = "PROXY UNKNOWN\r\n";
        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocol::FAMILY_UNKNOWN, $result->family);
        $this->assertNull($result->sourceAddress);
        $this->assertNull($result->sourcePort);
        $this->assertNull($result->destinationAddress);
        $this->assertNull($result->destinationPort);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testDecodeV1UnknownIgnoresTrailingTokens(): void
    {
        // Per spec: receivers MUST ignore everything past UNKNOWN on the line.
        $header = "PROXY UNKNOWN ff:ff::1 aa:aa::2 1234 5678\r\n";
        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocol::FAMILY_UNKNOWN, $result->family);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testDecodeV1ReturnsNullWhenCrlfMissing(): void
    {
        $this->assertNull(ProxyProtocol::decode('PROXY TCP4 1.2.3.4 5.6.7.8 1 2'));
    }

    public function testDecodeV1DoesNotConsumeTrailingData(): void
    {
        // Preamble is followed by a 4-byte payload; bytesConsumed must cover only the preamble.
        $preamble = "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n";
        $payload = "\x00\x0eABCD";
        $result = ProxyProtocol::decode($preamble . $payload);
        $this->assertNotNull($result);
        $this->assertSame(strlen($preamble), $result->bytesConsumed);
    }

    /** @return iterable<string, array{0: string}> */
    public static function malformedV1Provider(): iterable
    {
        yield 'non-digit port' => ["PROXY TCP4 1.2.3.4 5.6.7.8 abc 80\r\n"];
        yield 'leading zero port' => ["PROXY TCP4 1.2.3.4 5.6.7.8 080 81\r\n"];
        yield 'negative port' => ["PROXY TCP4 1.2.3.4 5.6.7.8 -1 80\r\n"];
        yield 'port out of range' => ["PROXY TCP4 1.2.3.4 5.6.7.8 70000 80\r\n"];
        yield 'invalid IPv4' => ["PROXY TCP4 999.999.999.999 10.0.0.1 1 2\r\n"];
        yield 'invalid IPv6' => ["PROXY TCP6 zz::1 2001:db8::2 1 2\r\n"];
        yield 'IPv4 under TCP6' => ["PROXY TCP6 1.2.3.4 5.6.7.8 1 2\r\n"];
        yield 'IPv6 under TCP4' => ["PROXY TCP4 2001:db8::1 10.0.0.1 1 2\r\n"];
        yield 'missing destination address' => ["PROXY TCP4 1.2.3.4 1 2\r\n"];
        yield 'extra token' => ["PROXY TCP4 1.2.3.4 5.6.7.8 1 2 3\r\n"];
        yield 'unsupported protocol' => ["PROXY HTTP 1.2.3.4 5.6.7.8 1 2\r\n"];
        yield 'double space' => ["PROXY  TCP4 1.2.3.4 5.6.7.8 1 2\r\n"];
        yield 'empty port' => ["PROXY TCP4 1.2.3.4 5.6.7.8  2\r\n"];
    }

    #[DataProvider('malformedV1Provider')]
    public function testDecodeV1MalformedThrows(string $header): void
    {
        $this->expectException(DecodingException::class);
        ProxyProtocol::decode($header);
    }

    public function testDecodeV1ThrowsWhenTooLong(): void
    {
        // 120+ bytes with no CRLF — exceeds the 107-byte cap.
        $buffer = 'PROXY TCP4 ' . str_repeat('a', 120);
        $this->expectException(DecodingException::class);
        ProxyProtocol::decode($buffer);
    }

    public function testDecodeV1ThrowsWhenLineLongerThan107Bytes(): void
    {
        // CRLF is present, but line length exceeds spec maximum.
        $longAddress = str_repeat('a', 100);
        $header = "PROXY TCP4 {$longAddress} 5.6.7.8 1 2\r\n";
        $this->assertGreaterThan(ProxyProtocol::V1_MAX_LENGTH, strlen($header));

        $this->expectException(DecodingException::class);
        ProxyProtocol::decode($header);
    }

    // ---------------------------------------------------------------------
    // decode() — v2
    // ---------------------------------------------------------------------

    private static function buildV2(int $verCmd, int $famTrans, string $payload): string
    {
        return ProxyProtocol::V2_SIGNATURE
            . chr($verCmd)
            . chr($famTrans)
            . pack('n', strlen($payload))
            . $payload;
    }

    public function testDecodeV2Inet4Tcp(): void
    {
        $payload = inet_pton('192.168.1.1') . inet_pton('10.0.0.1') . pack('nn', 56324, 443);
        $header = self::buildV2(0x21, 0x11, $payload);

        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocol::VERSION_2, $result->version);
        $this->assertFalse($result->isLocal);
        $this->assertSame(ProxyProtocol::FAMILY_TCP4, $result->family);
        $this->assertSame('192.168.1.1', $result->sourceAddress);
        $this->assertSame('10.0.0.1', $result->destinationAddress);
        $this->assertSame(56324, $result->sourcePort);
        $this->assertSame(443, $result->destinationPort);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testDecodeV2Inet4Udp(): void
    {
        $payload = inet_pton('127.0.0.1') . inet_pton('127.0.0.2') . pack('nn', 0, 65535);
        $header = self::buildV2(0x21, 0x12, $payload);

        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocol::FAMILY_UDP4, $result->family);
        $this->assertSame(0, $result->sourcePort);
        $this->assertSame(65535, $result->destinationPort);
    }

    public function testDecodeV2Inet6Tcp(): void
    {
        $payload = inet_pton('fe80::1') . inet_pton('fe80::2') . pack('nn', 11111, 22222);
        $header = self::buildV2(0x21, 0x21, $payload);

        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocol::FAMILY_TCP6, $result->family);
        $this->assertSame('fe80::1', $result->sourceAddress);
        $this->assertSame('fe80::2', $result->destinationAddress);
    }

    public function testDecodeV2Inet6Udp(): void
    {
        $payload = inet_pton('2001:db8::1') . inet_pton('2001:db8::2') . pack('nn', 53, 5353);
        $header = self::buildV2(0x21, 0x22, $payload);

        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocol::FAMILY_UDP6, $result->family);
        $this->assertSame('2001:db8::1', $result->sourceAddress);
        $this->assertSame('2001:db8::2', $result->destinationAddress);
    }

    public function testDecodeV2Local(): void
    {
        // LOCAL commands may carry any payload (health checks). We still
        // honour payload length, skip the body and return bytesConsumed.
        $payload = str_repeat("\x00", 12);
        $header = self::buildV2(0x20, 0x00, $payload);

        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertTrue($result->isLocal);
        $this->assertNull($result->sourceAddress);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testDecodeV2LocalEmptyPayload(): void
    {
        $header = self::buildV2(0x20, 0x00, '');
        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertTrue($result->isLocal);
        $this->assertSame(ProxyProtocol::V2_HEADER_LENGTH, $result->bytesConsumed);
    }

    public function testDecodeV2Unix(): void
    {
        $srcPath = str_pad('/var/run/src.sock', 108, "\x00");
        $dstPath = str_pad('/var/run/dst.sock', 108, "\x00");
        $payload = $srcPath . $dstPath;
        $header = self::buildV2(0x21, 0x31, $payload);

        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocol::FAMILY_UNIX, $result->family);
        $this->assertSame('/var/run/src.sock', $result->sourceAddress);
        $this->assertSame('/var/run/dst.sock', $result->destinationAddress);
        $this->assertNull($result->sourcePort);
        $this->assertNull($result->destinationPort);
    }

    public function testDecodeV2UnixEmptyPaths(): void
    {
        $payload = str_repeat("\x00", 216);
        $header = self::buildV2(0x21, 0x31, $payload);

        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertNull($result->sourceAddress);
        $this->assertNull($result->destinationAddress);
    }

    /** @return iterable<string, array{0: int}> */
    public static function v2UnknownFamilyTransportProvider(): iterable
    {
        yield 'UNSPEC family, STREAM transport' => [0x01];
        yield 'INET family, UNSPEC transport' => [0x10];
        yield 'INET family, reserved transport 3' => [0x13];
        yield 'reserved family 4, UNSPEC transport' => [0x40];
        yield 'reserved family 0xF, DGRAM transport' => [0xF2];
    }

    #[DataProvider('v2UnknownFamilyTransportProvider')]
    public function testDecodeV2UnknownFamilyOrTransportIsOpaque(int $famTrans): void
    {
        $payload = str_repeat("\x00", 12);
        $header = self::buildV2(0x21, $famTrans, $payload);

        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertSame(ProxyProtocol::FAMILY_UNKNOWN, $result->family);
        $this->assertFalse($result->isLocal);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    public function testDecodeV2WithTlvSuffixRespectsLength(): void
    {
        $addrPayload = inet_pton('192.168.1.1') . inet_pton('10.0.0.1') . pack('nn', 1, 2);
        $tlv = "\x03\x00\x04ABCD";
        $payload = $addrPayload . $tlv;
        $header = self::buildV2(0x21, 0x11, $payload);

        $result = ProxyProtocol::decode($header);

        $this->assertNotNull($result);
        $this->assertSame('192.168.1.1', $result->sourceAddress);
        $this->assertSame(strlen($header), $result->bytesConsumed);
    }

    /** @return iterable<string, array{0: string}> */
    public static function v2IncompleteProvider(): iterable
    {
        $payload = inet_pton('1.2.3.4') . inet_pton('5.6.7.8') . pack('nn', 1, 2);
        $full = ProxyProtocol::V2_SIGNATURE . chr(0x21) . chr(0x11) . pack('n', strlen($payload)) . $payload;

        yield 'header only, missing length bytes' => [substr($full, 0, 14)];
        yield 'header + half length' => [substr($full, 0, 15)];
        yield 'truncated address payload' => [substr($full, 0, strlen($full) - 1)];
        yield 'signature only' => [ProxyProtocol::V2_SIGNATURE];
        yield 'missing final byte' => [substr($full, 0, strlen($full) - 1)];
    }

    #[DataProvider('v2IncompleteProvider')]
    public function testDecodeV2ReturnsNullWhenIncomplete(string $buffer): void
    {
        $this->assertNull(ProxyProtocol::decode($buffer));
    }

    public function testDecodeV2InvalidVersionThrows(): void
    {
        $header = self::buildV2(0x31, 0x11, '');
        $this->expectException(DecodingException::class);
        ProxyProtocol::decode($header);
    }

    public function testDecodeV2InvalidCommandThrows(): void
    {
        // Version 2 (high nibble 0x2), command 0x5 (invalid).
        $header = self::buildV2(0x25, 0x11, '');
        $this->expectException(DecodingException::class);
        ProxyProtocol::decode($header);
    }

    public function testDecodeV2InetPayloadTooShortThrows(): void
    {
        // Declared INET+STREAM but only 4 bytes of payload — not enough.
        $header = self::buildV2(0x21, 0x11, str_repeat("\x00", 4));
        $this->expectException(DecodingException::class);
        ProxyProtocol::decode($header);
    }

    public function testDecodeV2UnixPayloadTooShortThrows(): void
    {
        $header = self::buildV2(0x21, 0x31, str_repeat("\x00", 100));
        $this->expectException(DecodingException::class);
        ProxyProtocol::decode($header);
    }

    public function testDecodeRejectsBufferNotStartingWithProxySignature(): void
    {
        $this->expectException(DecodingException::class);
        ProxyProtocol::decode("HELLO WORLD\r\n");
    }

    public function testDecodeReturnsNullForEmptyBuffer(): void
    {
        $this->assertNull(ProxyProtocol::decode(''));
    }

    // ---------------------------------------------------------------------
    // Streaming / chunked reads
    // ---------------------------------------------------------------------

    public function testDecodeV1StreamingProducesNullUntilCrlfSeen(): void
    {
        $full = "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n";
        $accumulator = '';

        for ($i = 0; $i < strlen($full) - 1; $i++) {
            $accumulator .= $full[$i];
            $this->assertNull(
                ProxyProtocol::decode($accumulator),
                "Expected null at byte {$i}"
            );
        }

        $accumulator .= $full[strlen($full) - 1];
        $this->assertNotNull(ProxyProtocol::decode($accumulator));
    }

    public function testDecodeV2StreamingProducesNullUntilTotalLength(): void
    {
        $payload = inet_pton('1.2.3.4') . inet_pton('5.6.7.8') . pack('nn', 1, 2);
        $full = self::buildV2(0x21, 0x11, $payload);

        for ($i = 1; $i < strlen($full); $i++) {
            $this->assertNull(
                ProxyProtocol::decode(substr($full, 0, $i)),
                "Expected null at partial length {$i}"
            );
        }

        $this->assertNotNull(ProxyProtocol::decode($full));
    }

    // ---------------------------------------------------------------------
    // Fuzz: random inputs never crash; they either decode, return null, or throw.
    // ---------------------------------------------------------------------

    public function testFuzzRandomBuffersDoNotCrash(): void
    {
        for ($i = 0; $i < 200; $i++) {
            $length = random_int(0, 128);
            $buffer = $length > 0 ? random_bytes($length) : '';

            try {
                ProxyProtocol::decode($buffer);
            } catch (DecodingException) {
                // Expected for malformed input.
            }

            // Reaching this point means the parser did not crash on the buffer.
            $this->addToAssertionCount(1);
        }
    }

    public function testFuzzRandomV2LikeBuffersDoNotCrash(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $addrLength = random_int(0, 64);
            $payload = $addrLength > 0 ? random_bytes($addrLength) : '';
            $verCmd = random_int(0, 255);
            $famTrans = random_int(0, 255);
            $buffer = self::buildV2($verCmd, $famTrans, $payload);

            try {
                ProxyProtocol::decode($buffer);
            } catch (DecodingException) {
                // Expected for malformed input.
            }

            // Reaching this point means the parser did not crash on the buffer.
            $this->addToAssertionCount(1);
        }
    }

    // ---------------------------------------------------------------------
    // Value object invariants
    // ---------------------------------------------------------------------

    public function testProxyProtocolIsReadonly(): void
    {
        $instance = new ProxyProtocol(
            version: ProxyProtocol::VERSION_1,
            isLocal: false,
            family: ProxyProtocol::FAMILY_TCP4,
            sourceAddress: '1.2.3.4',
            sourcePort: 80,
            destinationAddress: '5.6.7.8',
            destinationPort: 443,
            bytesConsumed: 40,
        );

        $this->expectException(\Error::class);
        /** @phpstan-ignore-next-line intentionally asserting readonly enforcement */
        $instance->version = ProxyProtocol::VERSION_2;
    }
}
