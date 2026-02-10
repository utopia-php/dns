<?php

namespace Tests\Unit\Utopia\DNS;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\DoHClient;

final class DoHClientTest extends TestCase
{
    public function testConstructorValidatesEndpoint(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid DoH endpoint URL.');

        new DoHClient('not-a-valid-url');
    }

    public function testConstructorValidatesMethod(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid HTTP method. Use GET or POST.');

        new DoHClient('https://cloudflare-dns.com/dns-query', 5, 'PUT');
    }

    public function testConstructorAcceptsValidEndpoint(): void
    {
        $client = new DoHClient('https://cloudflare-dns.com/dns-query');

        $this->assertSame('https://cloudflare-dns.com/dns-query', $client->getEndpoint());
        $this->assertSame(DoHClient::METHOD_POST, $client->getMethod());
    }

    public function testConstructorAcceptsGetMethod(): void
    {
        $client = new DoHClient('https://dns.google/dns-query', 5, DoHClient::METHOD_GET);

        $this->assertSame('https://dns.google/dns-query', $client->getEndpoint());
        $this->assertSame(DoHClient::METHOD_GET, $client->getMethod());
    }

    public function testConstructorAcceptsPostMethod(): void
    {
        $client = new DoHClient('https://dns.google/dns-query', 5, DoHClient::METHOD_POST);

        $this->assertSame('https://dns.google/dns-query', $client->getEndpoint());
        $this->assertSame(DoHClient::METHOD_POST, $client->getMethod());
    }

    public function testMethodConstants(): void
    {
        $this->assertSame('GET', DoHClient::METHOD_GET);
        $this->assertSame('POST', DoHClient::METHOD_POST);
    }
}
