<?php

namespace Utopia\Tests\DNS\Resolver;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Resolver\Memory;

class MemoryTest extends TestCase
{
    public function testResolveReturnsExactRecord(): void
    {
        $resolver = $this->createResolver();

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'www.example.com',
                type: Record::TYPE_A
            )
        ));

        $this->assertSame(Message::RCODE_NOERROR, $response->header->responseCode);
        $this->assertCount(1, $response->answers);
        $this->assertSame('www.example.com', $response->answers[0]->name);
        $this->assertSame(Record::TYPE_A, $response->answers[0]->type);
        $this->assertSame('192.0.2.10', $response->answers[0]->rdata);
        $this->assertEmpty($response->authority);
    }

    public function testResolveNoDataIncludesAuthority(): void
    {
        $resolver = $this->createResolver();

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'www.example.com',
                type: Record::TYPE_AAAA
            )
        ));

        $this->assertSame(Message::RCODE_NOERROR, $response->header->responseCode);
        $this->assertEmpty($response->answers);
        $this->assertNotEmpty($response->authority);
        $this->assertSame(Record::TYPE_SOA, $response->authority[0]->type);
    }

    public function testResolveNxDomain(): void
    {
        $resolver = $this->createResolver();

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'missing.example.com',
                type: Record::TYPE_A
            )
        ));

        $this->assertSame(Message::RCODE_NXDOMAIN, $response->header->responseCode);
        $this->assertEmpty($response->answers);
        $this->assertNotEmpty($response->authority);
        $this->assertSame(Record::TYPE_SOA, $response->authority[0]->type);
    }

    public function testResolveSoaFallsBackToParentZone(): void
    {
        $resolver = $this->createResolver();

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'child.www.example.com',
                type: Record::TYPE_SOA
            )
        ));

        $this->assertSame(Message::RCODE_NXDOMAIN, $response->header->responseCode);
        $this->assertEmpty($response->answers);
        $this->assertNotEmpty($response->authority);
        $this->assertSame(Record::TYPE_SOA, $response->authority[0]->type);
        $this->assertSame('example.com', $response->authority[0]->name);
    }

    private function createResolver(): Memory
    {
        $resolver = new Memory();

        $resolver->addRecord(new Record(
            name: 'example.com',
            type: Record::TYPE_SOA,
            rdata: 'ns1.example.com. admin.example.com. 1 3600 600 1209600 300'
        ));

        $resolver->addRecord(new Record(
            name: 'www.example.com',
            type: Record::TYPE_A,
            rdata: '192.0.2.10'
        ));

        return $resolver;
    }
}
