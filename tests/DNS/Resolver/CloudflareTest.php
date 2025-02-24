<?php

namespace Utopia\Tests\DNS\Resolver;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Record;
use Utopia\DNS\Resolver\Cloudflare;

class CloudflareTest extends TestCase
{
    private Cloudflare $resolver;

    protected function setUp(): void
    {
        $this->resolver = new Cloudflare();
    }

    public function testResolveGoogleA(): void
    {
        $records = $this->resolver->resolve([
            'domain' => 'google.com',
            'type' => 'A'
        ]);

        $this->assertIsArray($records);
        $this->assertNotEmpty($records);
        $this->assertInstanceOf(Record::class, $records[0] ?? null);

        /** @var Record $record */
        $record = $records[0];
        $this->assertEquals('A', $record->getTypeName());
        $this->assertEquals('google.com', $record->getName());
        $this->assertNotFalse(filter_var($record->getRdata(), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4));
    }

    public function testResolveGoogleAAAA(): void
    {
        $records = $this->resolver->resolve([
            'domain' => 'google.com',
            'type' => 'AAAA'
        ]);

        $this->assertIsArray($records);
        $this->assertNotEmpty($records);
        $this->assertInstanceOf(Record::class, $records[0] ?? null);

        /** @var Record $record */
        $record = $records[0];
        $this->assertEquals('AAAA', $record->getTypeName());
        $this->assertEquals('google.com', $record->getName());
        $this->assertNotFalse(filter_var($record->getRdata(), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6));
    }
}
