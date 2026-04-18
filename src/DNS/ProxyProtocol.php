<?php

namespace Utopia\DNS;

use Utopia\DNS\Exception\ProxyProtocol\DecodingException;

/**
 * Parser for the HAProxy PROXY protocol (v1 text and v2 binary).
 *
 * Used to recover the original client address when a DNS server is fronted by
 * a proxy or load balancer that prepends the PROXY header to each connection
 * (TCP) or packet (UDP). Spec:
 * https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
 */
final class ProxyProtocol
{
    /** v1 header starts with this ASCII prefix. */
    public const string V1_PREFIX = "PROXY ";

    /** v2 header starts with this 12-byte binary signature. */
    public const string V2_SIGNATURE = "\r\n\r\n\x00\r\nQUIT\n";

    /** Per spec, v1 line (including CRLF) is at most 107 bytes. */
    public const int V1_MAX_LENGTH = 107;

    /** v2 fixed header (signature + 4 bytes) before the address payload. */
    public const int V2_FIXED_HEADER_LENGTH = 16;

    /**
     * Detect which PROXY protocol version the buffer starts with.
     *
     * Returns 1 or 2 on a full match, 0 when the buffer is definitely not a
     * PROXY header, and null when the buffer is a valid prefix of a signature
     * but more bytes are needed to decide.
     */
    public static function detect(string $buffer): ?int
    {
        $length = strlen($buffer);

        if ($length === 0) {
            return null;
        }

        if (str_starts_with($buffer, self::V2_SIGNATURE)) {
            return 2;
        }

        if ($length < strlen(self::V2_SIGNATURE) && str_starts_with(self::V2_SIGNATURE, $buffer)) {
            return null;
        }

        if (str_starts_with($buffer, self::V1_PREFIX)) {
            return 1;
        }

        if ($length < strlen(self::V1_PREFIX) && str_starts_with(self::V1_PREFIX, $buffer)) {
            return null;
        }

        return 0;
    }

    /**
     * Parse the PROXY header at the beginning of the buffer.
     *
     * Returns null when more bytes are needed. Throws DecodingException if
     * the buffer begins with a PROXY signature but the header is malformed.
     * Callers must first ensure the buffer actually starts with a PROXY
     * signature (for example via {@see detect()}); this method does not
     * silently skip non-PROXY data.
     */
    public static function parse(string $buffer): ?ProxyProtocolHeader
    {
        $version = self::detect($buffer);

        if ($version === null) {
            return null;
        }

        if ($version === 0) {
            throw new DecodingException('Buffer does not start with a PROXY protocol signature.');
        }

        return $version === 1
            ? self::parseV1($buffer)
            : self::parseV2($buffer);
    }

    private static function parseV1(string $buffer): ?ProxyProtocolHeader
    {
        $terminator = strpos($buffer, "\r\n");

        if ($terminator === false) {
            if (strlen($buffer) >= self::V1_MAX_LENGTH) {
                throw new DecodingException('PROXY v1 header missing CRLF within 107 bytes.');
            }
            return null;
        }

        $lineLength = $terminator + 2;

        if ($lineLength > self::V1_MAX_LENGTH) {
            throw new DecodingException('PROXY v1 header exceeds 107 bytes.');
        }

        $line = substr($buffer, 0, $terminator);
        $parts = explode(' ', $line);

        if ($parts[0] !== 'PROXY') {
            throw new DecodingException('PROXY v1 header missing PROXY token.');
        }

        $proto = $parts[1] ?? '';

        if ($proto === 'UNKNOWN') {
            return new ProxyProtocolHeader(
                version: 1,
                isLocal: false,
                family: ProxyProtocolHeader::FAMILY_UNKNOWN,
                sourceAddress: null,
                sourcePort: null,
                destinationAddress: null,
                destinationPort: null,
                bytesConsumed: $lineLength,
            );
        }

        if ($proto !== 'TCP4' && $proto !== 'TCP6') {
            throw new DecodingException('PROXY v1 header has unsupported protocol: ' . $proto);
        }

        if (count($parts) !== 6) {
            throw new DecodingException('PROXY v1 header is malformed.');
        }

        [, , $srcAddr, $dstAddr, $srcPort, $dstPort] = $parts;

        $expectedFlag = $proto === 'TCP4' ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6;

        if (filter_var($srcAddr, FILTER_VALIDATE_IP, $expectedFlag) === false) {
            throw new DecodingException('PROXY v1 invalid source address: ' . $srcAddr);
        }

        if (filter_var($dstAddr, FILTER_VALIDATE_IP, $expectedFlag) === false) {
            throw new DecodingException('PROXY v1 invalid destination address: ' . $dstAddr);
        }

        $srcPortInt = self::parsePort($srcPort, 'source');
        $dstPortInt = self::parsePort($dstPort, 'destination');

        return new ProxyProtocolHeader(
            version: 1,
            isLocal: false,
            family: $proto,
            sourceAddress: $srcAddr,
            sourcePort: $srcPortInt,
            destinationAddress: $dstAddr,
            destinationPort: $dstPortInt,
            bytesConsumed: $lineLength,
        );
    }

    private static function parseV2(string $buffer): ?ProxyProtocolHeader
    {
        if (strlen($buffer) < self::V2_FIXED_HEADER_LENGTH) {
            return null;
        }

        $verCmd = ord($buffer[12]);
        $famTrans = ord($buffer[13]);

        $version = ($verCmd & 0xF0) >> 4;
        $command = $verCmd & 0x0F;

        if ($version !== 2) {
            throw new DecodingException('PROXY v2 header has invalid version: ' . $version);
        }

        if ($command !== 0 && $command !== 1) {
            throw new DecodingException('PROXY v2 header has invalid command: ' . $command);
        }

        $addressFamily = ($famTrans & 0xF0) >> 4;
        $transport = $famTrans & 0x0F;

        $payloadLengthData = unpack('n', substr($buffer, 14, 2));

        if ($payloadLengthData === false || !isset($payloadLengthData[1]) || !is_int($payloadLengthData[1])) {
            throw new DecodingException('PROXY v2 header has invalid payload length.');
        }

        $payloadLength = $payloadLengthData[1];
        $totalLength = self::V2_FIXED_HEADER_LENGTH + $payloadLength;

        if (strlen($buffer) < $totalLength) {
            return null;
        }

        $isLocal = $command === 0;

        // LOCAL connections carry no usable address info (health checks).
        if ($isLocal) {
            return new ProxyProtocolHeader(
                version: 2,
                isLocal: true,
                family: ProxyProtocolHeader::FAMILY_UNKNOWN,
                sourceAddress: null,
                sourcePort: null,
                destinationAddress: null,
                destinationPort: null,
                bytesConsumed: $totalLength,
            );
        }

        $payload = substr($buffer, self::V2_FIXED_HEADER_LENGTH, $payloadLength);

        return match (true) {
            $addressFamily === 0x1 && ($transport === 0x1 || $transport === 0x2) =>
                self::parseV2Inet($payload, $transport, $totalLength, 4),
            $addressFamily === 0x2 && ($transport === 0x1 || $transport === 0x2) =>
                self::parseV2Inet($payload, $transport, $totalLength, 16),
            $addressFamily === 0x3 && ($transport === 0x1 || $transport === 0x2) =>
                self::parseV2Unix($payload, $totalLength),
            default => new ProxyProtocolHeader(
                version: 2,
                isLocal: false,
                family: ProxyProtocolHeader::FAMILY_UNKNOWN,
                sourceAddress: null,
                sourcePort: null,
                destinationAddress: null,
                destinationPort: null,
                bytesConsumed: $totalLength,
            ),
        };
    }

    private static function parseV2Inet(string $payload, int $transport, int $totalLength, int $addrSize): ProxyProtocolHeader
    {
        $expected = ($addrSize * 2) + 4;

        if (strlen($payload) < $expected) {
            throw new DecodingException('PROXY v2 INET payload too short.');
        }

        $srcRaw = substr($payload, 0, $addrSize);
        $dstRaw = substr($payload, $addrSize, $addrSize);

        $srcAddr = inet_ntop($srcRaw);
        $dstAddr = inet_ntop($dstRaw);

        if ($srcAddr === false || $dstAddr === false) {
            throw new DecodingException('PROXY v2 INET address could not be decoded.');
        }

        $ports = unpack('nsrc/ndst', substr($payload, $addrSize * 2, 4));

        if ($ports === false || !is_int($ports['src'] ?? null) || !is_int($ports['dst'] ?? null)) {
            throw new DecodingException('PROXY v2 INET ports could not be decoded.');
        }

        $ipv4 = $addrSize === 4;

        if ($transport === 0x1) {
            $family = $ipv4 ? ProxyProtocolHeader::FAMILY_TCP4 : ProxyProtocolHeader::FAMILY_TCP6;
        } else {
            $family = $ipv4 ? ProxyProtocolHeader::FAMILY_UDP4 : ProxyProtocolHeader::FAMILY_UDP6;
        }

        return new ProxyProtocolHeader(
            version: 2,
            isLocal: false,
            family: $family,
            sourceAddress: $srcAddr,
            sourcePort: $ports['src'],
            destinationAddress: $dstAddr,
            destinationPort: $ports['dst'],
            bytesConsumed: $totalLength,
        );
    }

    private static function parseV2Unix(string $payload, int $totalLength): ProxyProtocolHeader
    {
        if (strlen($payload) < 216) {
            throw new DecodingException('PROXY v2 UNIX payload too short.');
        }

        $src = rtrim(substr($payload, 0, 108), "\x00");
        $dst = rtrim(substr($payload, 108, 108), "\x00");

        return new ProxyProtocolHeader(
            version: 2,
            isLocal: false,
            family: ProxyProtocolHeader::FAMILY_UNIX,
            sourceAddress: $src !== '' ? $src : null,
            sourcePort: null,
            destinationAddress: $dst !== '' ? $dst : null,
            destinationPort: null,
            bytesConsumed: $totalLength,
        );
    }

    private static function parsePort(string $value, string $label): int
    {
        if ($value === '' || !ctype_digit($value)) {
            throw new DecodingException('PROXY v1 invalid ' . $label . ' port: ' . $value);
        }

        $port = (int) $value;

        if ($port < 0 || $port > 65535) {
            throw new DecodingException('PROXY v1 ' . $label . ' port out of range: ' . $value);
        }

        return $port;
    }
}
