<?php

namespace Utopia\DNS\Resolver;

use Utopia\DNS\DoHClient;

/**
 * Google DNS over HTTPS (DoH) Resolver
 *
 * Uses Google's public DoH endpoints:
 * - Primary: https://dns.google/dns-query
 * - Backup: https://dns.google/dns-query (same endpoint, Google handles load balancing)
 *
 * Note: Google's DNS infrastructure provides built-in redundancy,
 * so both endpoints resolve to the same highly-available service.
 *
 * @see https://developers.google.com/speed/public-dns/docs/doh
 */
class GoogleDoH extends DoH
{
    public const ENDPOINT_PRIMARY = 'https://dns.google/dns-query';
    public const ENDPOINT_BACKUP = 'https://dns.google/dns-query';

    /**
     * Create a new Google DoH resolver
     *
     * @param bool $useBackup Use backup endpoint instead of primary
     * @param int $timeout Request timeout in seconds
     * @param string $method HTTP method to use (GET or POST)
     */
    public function __construct(
        bool $useBackup = false,
        int $timeout = 5,
        string $method = DoHClient::METHOD_POST
    ) {
        $endpoint = $useBackup ? self::ENDPOINT_BACKUP : self::ENDPOINT_PRIMARY;
        parent::__construct($endpoint, $timeout, $method);
    }

    /**
     * Get the name of the resolver
     *
     * @return string The resolver name
     */
    public function getName(): string
    {
        return "Google DoH ($this->endpoint)";
    }
}
