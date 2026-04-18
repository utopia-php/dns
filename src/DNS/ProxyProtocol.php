<?php

namespace Utopia\DNS;

use Utopia\DNS\Exception\ProxyProtocol\DecodingException;

/**
 * Parsed HAProxy PROXY protocol preamble (v1 text or v2 binary).
 *
 * Used to recover the original client address when a DNS server is fronted
 * by a proxy or load balancer that prepends a PROXY header to each TCP
 * connection or UDP datagram.
 *
 * Spec: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
 */
final readonly class ProxyProtocol
{
    public const int VERSION_1 = 1;

    public const int VERSION_2 = 2;

    public const int COMMAND_LOCAL = 0x0;

    public const int COMMAND_PROXY = 0x1;

    public const int ADDRESS_FAMILY_UNSPEC = 0x0;

    public const int ADDRESS_FAMILY_INET = 0x1;

    public const int ADDRESS_FAMILY_INET6 = 0x2;

    public const int ADDRESS_FAMILY_UNIX = 0x3;

    public const int TRANSPORT_UNSPEC = 0x0;

    public const int TRANSPORT_STREAM = 0x1;

    public const int TRANSPORT_DGRAM = 0x2;

    public const string FAMILY_TCP4 = 'TCP4';

    public const string FAMILY_TCP6 = 'TCP6';

    public const string FAMILY_UDP4 = 'UDP4';

    public const string FAMILY_UDP6 = 'UDP6';

    public const string FAMILY_UNIX = 'UNIX';

    public const string FAMILY_UNKNOWN = 'UNKNOWN';

    /** v1 preamble is an ASCII line starting with this prefix. */
    public const string V1_PREFIX = "PROXY ";

    /** v1 preamble (including CRLF) is at most 107 bytes per spec. */
    public const int V1_MAX_LENGTH = 107;

    /** v2 preamble starts with this 12-byte binary signature. */
    public const string V2_SIGNATURE = "\r\n\r\n\x00\r\nQUIT\n";

    /** v2 fixed header: 12-byte signature + 2-byte ver/cmd+fam/trans + 2-byte length. */
    public const int V2_HEADER_LENGTH = 16;

    public const int V2_SIGNATURE_LENGTH = 12;

    /** v2 INET address payload: 4-byte src + 4-byte dst + 2-byte src port + 2-byte dst port. */
    public const int V2_INET_PAYLOAD_LENGTH = 12;

    /** v2 INET6 address payload: 16-byte src + 16-byte dst + 2-byte src port + 2-byte dst port. */
    public const int V2_INET6_PAYLOAD_LENGTH = 36;

    /** v2 UNIX address payload: 108-byte src path + 108-byte dst path. */
    public const int V2_UNIX_PAYLOAD_LENGTH = 216;

    public function __construct(
        public int $version,
        public bool $isLocal,
        public string $family,
        public ?string $sourceAddress,
        public ?int $sourcePort,
        public ?string $destinationAddress,
        public ?int $destinationPort,
        public int $bytesConsumed,
    ) {
    }

    /**
     * Detect which PROXY protocol version the buffer starts with.
     *
     * Returns 1 or 2 on a full-signature match, 0 when the buffer is
     * definitely not a PROXY preamble, and null when the buffer is a valid
     * prefix of either signature but too short to decide.
     *
     * Hot path: the common case is non-PROXY DNS traffic, where the first
     * byte is a random transaction ID byte. This returns 0 after a single
     * byte comparison in that case.
     */
    public static function detect(string $buffer): ?int
    {
        if ($buffer === '') {
            return null;
        }

        $first = $buffer[0];

        // v1 starts with ASCII 'P'. v2 starts with 0x0D ('\r'). Anything else is not PROXY.
        if ($first === 'P') {
            if (\str_starts_with($buffer, self::V1_PREFIX)) {
                return self::VERSION_1;
            }

            if (\strlen($buffer) < 6 && \str_starts_with(self::V1_PREFIX, $buffer)) {
                return null;
            }

            return 0;
        }

        if ($first === "\r") {
            if (\str_starts_with($buffer, self::V2_SIGNATURE)) {
                return self::VERSION_2;
            }

            if (\strlen($buffer) < self::V2_SIGNATURE_LENGTH && \str_starts_with(self::V2_SIGNATURE, $buffer)) {
                return null;
            }

            return 0;
        }

        return 0;
    }

    /**
     * Decode a PROXY preamble from the beginning of the buffer.
     *
     * Returns null when the buffer is a valid partial preamble but more bytes
     * are needed. Throws {@see DecodingException} on malformed input or when
     * the buffer does not start with a PROXY signature. Callers that mix
     * PROXY and direct traffic should call {@see detect()} first.
     */
    public static function decode(string $buffer): ?self
    {
        $version = self::detect($buffer);

        if ($version === null) {
            return null;
        }

        if ($version === 0) {
            throw new DecodingException('Buffer does not start with a PROXY protocol signature.');
        }

        return $version === self::VERSION_1
            ? self::decodeV1($buffer)
            : self::decodeV2($buffer);
    }

    private static function decodeV1(string $buffer): ?self
    {
        $terminator = \strpos($buffer, "\r\n");

        if ($terminator === false) {
            if (\strlen($buffer) >= self::V1_MAX_LENGTH) {
                throw new DecodingException('PROXY v1 header missing CRLF within 107 bytes.');
            }
            return null;
        }

        $lineLength = $terminator + 2;

        if ($lineLength > self::V1_MAX_LENGTH) {
            throw new DecodingException('PROXY v1 header exceeds 107 bytes.');
        }

        $line = \substr($buffer, 0, $terminator);
        $parts = \explode(' ', $line);

        if ($parts[0] !== 'PROXY') {
            throw new DecodingException('PROXY v1 header missing PROXY token.');
        }

        $proto = $parts[1] ?? '';

        // Per spec: receivers MUST ignore everything past UNKNOWN on the line.
        if ($proto === 'UNKNOWN') {
            return new self(
                version: self::VERSION_1,
                isLocal: false,
                family: self::FAMILY_UNKNOWN,
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

        if (\count($parts) !== 6) {
            throw new DecodingException('PROXY v1 header is malformed.');
        }

        [, , $srcAddr, $dstAddr, $srcPort, $dstPort] = $parts;

        $ipFlag = $proto === 'TCP4' ? \FILTER_FLAG_IPV4 : \FILTER_FLAG_IPV6;

        if (\filter_var($srcAddr, \FILTER_VALIDATE_IP, $ipFlag) === false) {
            throw new DecodingException('PROXY v1 invalid source address: ' . $srcAddr);
        }

        if (\filter_var($dstAddr, \FILTER_VALIDATE_IP, $ipFlag) === false) {
            throw new DecodingException('PROXY v1 invalid destination address: ' . $dstAddr);
        }

        return new self(
            version: self::VERSION_1,
            isLocal: false,
            family: $proto,
            sourceAddress: $srcAddr,
            sourcePort: self::decodeV1Port($srcPort, 'source'),
            destinationAddress: $dstAddr,
            destinationPort: self::decodeV1Port($dstPort, 'destination'),
            bytesConsumed: $lineLength,
        );
    }

    private static function decodeV1Port(string $value, string $label): int
    {
        if (!\ctype_digit($value) || ($value[0] === '0' && $value !== '0')) {
            throw new DecodingException('PROXY v1 invalid ' . $label . ' port: ' . $value);
        }

        $port = (int) $value;

        if ($port > 65535) {
            throw new DecodingException('PROXY v1 ' . $label . ' port out of range: ' . $value);
        }

        return $port;
    }

    private static function decodeV2(string $buffer): ?self
    {
        if (\strlen($buffer) < self::V2_HEADER_LENGTH) {
            return null;
        }

        // Single unpack call: ver/cmd byte, family/transport byte, 2-byte length.
        $fields = \unpack('CverCmd/CfamTrans/nlength', $buffer, self::V2_SIGNATURE_LENGTH);

        if ($fields === false
            || !\is_int($fields['verCmd'] ?? null)
            || !\is_int($fields['famTrans'] ?? null)
            || !\is_int($fields['length'] ?? null)
        ) {
            throw new DecodingException('PROXY v2 header could not be unpacked.');
        }

        $verCmd = $fields['verCmd'];
        $famTrans = $fields['famTrans'];
        $payloadLength = $fields['length'];

        if (($verCmd & 0xF0) !== 0x20) {
            throw new DecodingException('PROXY v2 header has invalid version.');
        }

        $command = $verCmd & 0x0F;

        if ($command !== self::COMMAND_LOCAL && $command !== self::COMMAND_PROXY) {
            throw new DecodingException('PROXY v2 header has invalid command: ' . $command);
        }

        $totalLength = self::V2_HEADER_LENGTH + $payloadLength;

        if (\strlen($buffer) < $totalLength) {
            return null;
        }

        if ($command === self::COMMAND_LOCAL) {
            return new self(
                version: self::VERSION_2,
                isLocal: true,
                family: self::FAMILY_UNKNOWN,
                sourceAddress: null,
                sourcePort: null,
                destinationAddress: null,
                destinationPort: null,
                bytesConsumed: $totalLength,
            );
        }

        $addressFamily = ($famTrans & 0xF0) >> 4;
        $transport = $famTrans & 0x0F;

        if ($transport !== self::TRANSPORT_STREAM && $transport !== self::TRANSPORT_DGRAM) {
            return self::opaqueV2($totalLength);
        }

        return match ($addressFamily) {
            self::ADDRESS_FAMILY_INET => self::decodeV2Inet(
                $buffer,
                $transport,
                $totalLength,
                self::V2_INET_PAYLOAD_LENGTH,
                4,
            ),
            self::ADDRESS_FAMILY_INET6 => self::decodeV2Inet(
                $buffer,
                $transport,
                $totalLength,
                self::V2_INET6_PAYLOAD_LENGTH,
                16,
            ),
            self::ADDRESS_FAMILY_UNIX => self::decodeV2Unix(
                $buffer,
                $payloadLength,
                $totalLength,
            ),
            default => self::opaqueV2($totalLength),
        };
    }

    private static function decodeV2Inet(string $buffer, int $transport, int $totalLength, int $minPayload, int $addrSize): self
    {
        if ($totalLength - self::V2_HEADER_LENGTH < $minPayload) {
            throw new DecodingException('PROXY v2 INET payload too short for declared family.');
        }

        $offset = self::V2_HEADER_LENGTH;

        $srcRaw = \substr($buffer, $offset, $addrSize);
        $dstRaw = \substr($buffer, $offset + $addrSize, $addrSize);
        $srcAddr = \inet_ntop($srcRaw);
        $dstAddr = \inet_ntop($dstRaw);

        if ($srcAddr === false || $dstAddr === false) {
            throw new DecodingException('PROXY v2 INET address could not be decoded.');
        }

        $ports = \unpack('nsrc/ndst', $buffer, $offset + ($addrSize * 2));

        if ($ports === false || !\is_int($ports['src'] ?? null) || !\is_int($ports['dst'] ?? null)) {
            throw new DecodingException('PROXY v2 INET ports could not be decoded.');
        }

        $isInet6 = $addrSize === 16;

        if ($transport === self::TRANSPORT_STREAM) {
            $family = $isInet6 ? self::FAMILY_TCP6 : self::FAMILY_TCP4;
        } else {
            $family = $isInet6 ? self::FAMILY_UDP6 : self::FAMILY_UDP4;
        }

        return new self(
            version: self::VERSION_2,
            isLocal: false,
            family: $family,
            sourceAddress: $srcAddr,
            sourcePort: $ports['src'],
            destinationAddress: $dstAddr,
            destinationPort: $ports['dst'],
            bytesConsumed: $totalLength,
        );
    }

    private static function decodeV2Unix(string $buffer, int $payloadLength, int $totalLength): self
    {
        if ($payloadLength < self::V2_UNIX_PAYLOAD_LENGTH) {
            throw new DecodingException('PROXY v2 UNIX payload too short.');
        }

        $offset = self::V2_HEADER_LENGTH;
        $src = \rtrim(\substr($buffer, $offset, 108), "\x00");
        $dst = \rtrim(\substr($buffer, $offset + 108, 108), "\x00");

        return new self(
            version: self::VERSION_2,
            isLocal: false,
            family: self::FAMILY_UNIX,
            sourceAddress: $src !== '' ? $src : null,
            sourcePort: null,
            destinationAddress: $dst !== '' ? $dst : null,
            destinationPort: null,
            bytesConsumed: $totalLength,
        );
    }

    /**
     * v2 headers with an unknown family or transport are passed through as
     * opaque frames: we still advance past them so downstream parsing lines
     * up, but the address info is discarded.
     */
    private static function opaqueV2(int $totalLength): self
    {
        return new self(
            version: self::VERSION_2,
            isLocal: false,
            family: self::FAMILY_UNKNOWN,
            sourceAddress: null,
            sourcePort: null,
            destinationAddress: null,
            destinationPort: null,
            bytesConsumed: $totalLength,
        );
    }
}
