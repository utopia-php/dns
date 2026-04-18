<?php

namespace Tests\E2E\Utopia\DNS\Resolver;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\DoHClient;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Resolver\DoH;

final class DoHTest extends TestCase
{
    public function testResolveWithCustomEndpoint(): void
    {
        // Using Cloudflare's endpoint as a custom endpoint
        $resolver = new DoH('https://cloudflare-dns.com/dns-query');

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'example.com',
                type: Record::TYPE_A
            )
        ));

        $this->assertNotEmpty($response->answers);
        $this->assertInstanceOf(Record::class, $response->answers[0] ?? null);

        /** @var Record $record */
        $record = $response->answers[0];
        $this->assertSame(Record::TYPE_A, $record->type);
        $this->assertSame('example.com', $record->name);
        $this->assertNotFalse(filter_var($record->rdata, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4));
    }

    public function testResolveWithGetMethod(): void
    {
        $resolver = new DoH('https://cloudflare-dns.com/dns-query', 5, DoHClient::METHOD_GET);

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'example.com',
                type: Record::TYPE_A
            )
        ));

        $this->assertNotEmpty($response->answers);
        $this->assertInstanceOf(Record::class, $response->answers[0] ?? null);
    }

    public function testResolveWithPostMethod(): void
    {
        $resolver = new DoH('https://cloudflare-dns.com/dns-query', 5, DoHClient::METHOD_POST);

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'example.com',
                type: Record::TYPE_A
            )
        ));

        $this->assertNotEmpty($response->answers);
        $this->assertInstanceOf(Record::class, $response->answers[0] ?? null);
    }

    public function testGetName(): void
    {
        $resolver = new DoH('https://custom-dns.example.com/dns-query');
        $this->assertSame('DoH (https://custom-dns.example.com/dns-query)', $resolver->getName());
    }

    public function testGetClient(): void
    {
        $resolver = new DoH('https://cloudflare-dns.com/dns-query', 10, DoHClient::METHOD_GET);
        $client = $resolver->getClient();

        $this->assertInstanceOf(DoHClient::class, $client);
        $this->assertSame('https://cloudflare-dns.com/dns-query', $client->getEndpoint());
        $this->assertSame(DoHClient::METHOD_GET, $client->getMethod());
    }

    public function testResolveTXTRecord(): void
    {
        $resolver = new DoH('https://cloudflare-dns.com/dns-query');

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'google.com',
                type: Record::TYPE_TXT
            )
        ));

        $this->assertNotEmpty($response->answers);

        $hasTxt = false;
        foreach ($response->answers as $record) {
            if ($record->type === Record::TYPE_TXT) {
                $hasTxt = true;
                break;
            }
        }
        $this->assertTrue($hasTxt, 'Response should contain TXT records');
    }

    public function testResolveNSRecord(): void
    {
        $resolver = new DoH('https://cloudflare-dns.com/dns-query');

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'google.com',
                type: Record::TYPE_NS
            )
        ));

        $this->assertNotEmpty($response->answers);

        /** @var Record $record */
        $record = $response->answers[0];
        $this->assertSame(Record::TYPE_NS, $record->type);
        $this->assertSame('google.com', $record->name);
    }
}
