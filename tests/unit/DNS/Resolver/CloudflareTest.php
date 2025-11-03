<?php

namespace Tests\Unit\Utopia\DNS\Resolver;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Resolver\Cloudflare;

class CloudflareTest extends TestCase
{
    public function testResolveGoogleA(): void
    {
        $resolver = new Cloudflare();

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'google.com',
                type: Record::TYPE_A
            )
        ));

        $this->assertNotEmpty($response->answers);
        $this->assertInstanceOf(Record::class, $response->answers[0] ?? null);

        /** @var Record $record */
        $record = $response->answers[0];
        $this->assertEquals(Record::TYPE_A, $record->type);
        $this->assertEquals('google.com', $record->name);
        $this->assertNotFalse(filter_var($record->rdata, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4));
    }

    public function testResolveGoogleAAAA(): void
    {
        $resolver = new Cloudflare();

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'google.com',
                type: Record::TYPE_AAAA
            )
        ));

        $this->assertNotEmpty($response->answers);
        $this->assertInstanceOf(Record::class, $response->answers[0] ?? null);

        /** @var Record $record */
        $record = $response->answers[0];
        $this->assertEquals(Record::TYPE_AAAA, $record->type);
        $this->assertEquals('google.com', $record->name);
        $this->assertNotFalse(filter_var($record->rdata, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6));
    }
}
