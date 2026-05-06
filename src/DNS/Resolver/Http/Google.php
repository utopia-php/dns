<?php

namespace Utopia\DNS\Resolver\Http;

use Utopia\DNS\Http\Client;
use Utopia\DNS\Resolver\Http;

/**
 * Google DNS over HTTPS Resolver
 *
 * Uses Google's public DoH endpoints:
 * - Primary: https://dns.google/dns-query
 * - Backup: https://8.8.8.8/dns-query (IP-addressed; survives DNS resolution failure for dns.google)
 *
 * @see https://developers.google.com/speed/public-dns/docs/doh
 */
class Google extends Http
{
    public const ENDPOINT_PRIMARY = 'https://dns.google/dns-query';
    public const ENDPOINT_BACKUP = 'https://8.8.8.8/dns-query';

    /**
     * Create a new Google HTTP (DoH) resolver
     *
     * @param bool $useBackup Use backup endpoint instead of primary
     * @param int $timeout Total request timeout in seconds
     * @param int $connectTimeout Connection timeout in seconds
     * @param string $method HTTP method to use (GET or POST)
     */
    public function __construct(
        bool $useBackup = false,
        int $timeout = 5,
        int $connectTimeout = 2,
        string $method = Client::METHOD_POST
    ) {
        $endpoint = $useBackup ? self::ENDPOINT_BACKUP : self::ENDPOINT_PRIMARY;
        parent::__construct($endpoint, $timeout, $connectTimeout, $method);
    }

    /**
     * Get the name of the resolver
     *
     * @return string The resolver name
     */
    public function getName(): string
    {
        return "Google HTTP ($this->endpoint)";
    }
}
