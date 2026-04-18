<?php

namespace Utopia\DNS;

/**
 * Parsed PROXY protocol header.
 *
 * Represents the source/destination endpoints announced by a PROXY protocol
 * (v1 or v2) preamble. See HAProxy's PROXY protocol spec for reference:
 * https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
 */
final class ProxyProtocolHeader
{
    public const string FAMILY_TCP4 = 'TCP4';
    public const string FAMILY_TCP6 = 'TCP6';
    public const string FAMILY_UDP4 = 'UDP4';
    public const string FAMILY_UDP6 = 'UDP6';
    public const string FAMILY_UNIX = 'UNIX';
    public const string FAMILY_UNKNOWN = 'UNKNOWN';

    public function __construct(
        public readonly int $version,
        public readonly bool $isLocal,
        public readonly string $family,
        public readonly ?string $sourceAddress,
        public readonly ?int $sourcePort,
        public readonly ?string $destinationAddress,
        public readonly ?int $destinationPort,
        public readonly int $bytesConsumed,
    ) {
    }
}
