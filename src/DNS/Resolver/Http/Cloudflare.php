<?php

namespace Utopia\DNS\Resolver\Http;

use Utopia\DNS\Http\Client;
use Utopia\DNS\Resolver\Http;

/**
 * Cloudflare DNS over HTTPS Resolver
 *
 * Uses Cloudflare's public DoH endpoints:
 * - Primary: https://cloudflare-dns.com/dns-query
 * - Backup: https://one.one.one.one/dns-query
 *
 * @see https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/
 */
class Cloudflare extends Http
{
    public const ENDPOINT_PRIMARY = 'https://cloudflare-dns.com/dns-query';
    public const ENDPOINT_BACKUP = 'https://one.one.one.one/dns-query';

    /**
     * Create a new Cloudflare HTTP (DoH) resolver
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
        return "Cloudflare HTTP ($this->endpoint)";
    }
}
