<?php

namespace Tests\Unit\Utopia\DNS\Http;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Http\Client;

final class ClientTest extends TestCase
{
    public function testConstructorValidatesEndpoint(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid DoH endpoint URL. Must be a valid HTTPS URL.');

        new Client('not-a-valid-url');
    }

    public function testConstructorRejectsHttpScheme(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid DoH endpoint URL. Must be a valid HTTPS URL.');

        new Client('http://example.com/dns-query');
    }

    public function testConstructorValidatesMethod(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid HTTP method. Use GET or POST.');

        new Client('https://cloudflare-dns.com/dns-query', 5, 2, 'PUT');
    }

    public function testConstructorAcceptsValidEndpoint(): void
    {
        $client = new Client('https://cloudflare-dns.com/dns-query');

        $this->assertSame('https://cloudflare-dns.com/dns-query', $client->getEndpoint());
        $this->assertSame(Client::METHOD_POST, $client->getMethod());
    }

    public function testConstructorAcceptsGetMethod(): void
    {
        $client = new Client('https://dns.google/dns-query', 5, 2, Client::METHOD_GET);

        $this->assertSame('https://dns.google/dns-query', $client->getEndpoint());
        $this->assertSame(Client::METHOD_GET, $client->getMethod());
    }

    public function testConstructorAcceptsPostMethod(): void
    {
        $client = new Client('https://dns.google/dns-query', 5, 2, Client::METHOD_POST);

        $this->assertSame('https://dns.google/dns-query', $client->getEndpoint());
        $this->assertSame(Client::METHOD_POST, $client->getMethod());
    }

    public function testMethodConstants(): void
    {
        $this->assertSame('GET', Client::METHOD_GET);
        $this->assertSame('POST', Client::METHOD_POST);
    }
}
