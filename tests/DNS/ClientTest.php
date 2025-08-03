<?php

namespace Utopia\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Client;
use Utopia\DNS\Record;

class ClientTest extends TestCase
{
    /**
     * @var Client
     */
    private Client $client;

    protected function setUp(): void
    {
        // Use a custom DNS server (e.g., 127.0.0.1:5300)
        $this->client = new Client('localhost', 53);
    }

    public function testARecords(): void
    {
        $records = $this->client->query('dev.appwrite.io', 'A');

        $this->assertCount(1, $records);
        $this->assertInstanceOf(Record::class, $records[0]);
        $this->assertEquals('dev.appwrite.io', $records[0]->getName());
        $this->assertEquals('IN', $records[0]->getClass());
        $this->assertIsNumeric($records[0]->getTTL());
        $this->assertEquals(10, $records[0]->getTTL());
        $this->assertEquals('A', $records[0]->getTypeName());
        $this->assertEquals('180.12.3.24', $records[0]->getRdata());

        $records = $this->client->query('dev2.appwrite.io', 'A');

        $this->assertCount(2, $records);
        $this->assertEquals('dev2.appwrite.io', $records[0]->getName());
        $this->assertEquals('IN', $records[0]->getClass());
        $this->assertIsNumeric($records[0]->getTTL());
        $this->assertEquals(1800, $records[0]->getTTL());
        $this->assertEquals('A', $records[0]->getTypeName());
        $this->assertEquals('142.6.0.1', $records[0]->getRdata());
        $this->assertEquals('142.6.0.2', $records[1]->getRdata());

        $records = $this->client->query('dev3.appwrite.io', 'A');
        $this->assertCount(0, $records);
    }

    public function testAAAARecords(): void
    {
        $records = $this->client->query('dev.appwrite.io', 'AAAA');

        $this->assertCount(1, $records);
        $this->assertEquals('dev.appwrite.io', $records[0]->getName());
        $this->assertEquals('IN', $records[0]->getClass());
        $this->assertIsNumeric($records[0]->getTTL());
        $this->assertEquals(20, $records[0]->getTTL());
        $this->assertEquals('AAAA', $records[0]->getTypeName());
        $this->assertEquals('2001:db8::ff00:42:8329', $records[0]->getRdata());

        $records = $this->client->query('dev2.appwrite.io', 'AAAA');

        $this->assertCount(2, $records);
        $this->assertEquals('2001:db8::ff00:0:1', $records[0]->getRdata());
        $this->assertEquals('2001:db8::ff00:0:2', $records[1]->getRdata());

        $records = $this->client->query('dev3.appwrite.io', 'AAAA');
        $this->assertCount(0, $records);
    }

    public function testCNAMERecords(): void
    {
        $records = $this->client->query('dev.appwrite.io', 'CNAME');

        $this->assertCount(1, $records);
        $this->assertEquals('dev.appwrite.io', $records[0]->getName());
        $this->assertEquals('IN', $records[0]->getClass());
        $this->assertIsNumeric($records[0]->getTTL());
        $this->assertEquals(30, $records[0]->getTTL());
        $this->assertEquals('CNAME', $records[0]->getTypeName());
        $this->assertEquals('cloud.appwrite.io', $records[0]->getRdata());

        $records = $this->client->query('dev2.appwrite.io', 'CNAME');

        $this->assertCount(2, $records);
        $this->assertEquals('eu.cloud.appwrite.io', $records[0]->getRdata());
        $this->assertEquals('us.cloud.appwrite.io', $records[1]->getRdata());

        $records = $this->client->query('dev3.appwrite.io', 'CNAME');
        $this->assertCount(0, $records);
    }

    public function testTXTRecords(): void
    {
        $records = $this->client->query('dev.appwrite.io', 'TXT');

        $this->assertCount(1, $records);
        $this->assertEquals('dev.appwrite.io', $records[0]->getName());
        $this->assertEquals('IN', $records[0]->getClass());
        $this->assertIsNumeric($records[0]->getTTL());
        $this->assertEquals(40, $records[0]->getTTL());
        $this->assertEquals('TXT', $records[0]->getTypeName());
        $this->assertEquals('awesome-secret-key', $records[0]->getRdata());

        $records = $this->client->query('dev2.appwrite.io', 'TXT');

        $this->assertCount(3, $records);
        $this->assertEquals('key with "$\'- symbols', $records[0]->getRdata());
        $this->assertEquals('key with spaces', $records[1]->getRdata());
        $this->assertEquals('v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1;', $records[2]->getRdata());

        $records = $this->client->query('dev3.appwrite.io', 'TXT');
        $this->assertCount(0, $records);
    }

    public function testNSRecords(): void
    {
        $records = $this->client->query('dev.appwrite.io', 'NS');

        $this->assertCount(1, $records);
        $this->assertEquals('dev.appwrite.io', $records[0]->getName());
        $this->assertEquals('IN', $records[0]->getClass());
        $this->assertIsNumeric($records[0]->getTTL());
        $this->assertEquals(60, $records[0]->getTTL());
        $this->assertEquals('NS', $records[0]->getTypeName());
        $this->assertEquals('ns.appwrite.io', $records[0]->getRdata());

        $records = $this->client->query('dev2.appwrite.io', 'NS');

        $this->assertCount(2, $records);
        $this->assertEquals('ns1.appwrite.io', $records[0]->getRdata());
        $this->assertEquals('ns2.appwrite.io', $records[1]->getRdata());

        $records = $this->client->query('dev3.appwrite.io', 'NS');
        $this->assertCount(0, $records);
    }

    public function testCAARecords(): void
    {
        $records = $this->client->query('github.com', 'CAA');

        $this->assertCount(1, $records);
        $this->assertEquals('github.com', $records[0]->getName());
        $this->assertEquals('IN', $records[0]->getClass());
        $this->assertIsNumeric($records[0]->getTTL());
        $this->assertEquals('CAA', $records[0]->getTypeName());
        
        $rdata = $records[0]->getRdata();
        $this->assertStringContainsString('Flags:', $rdata);
        $this->assertStringContainsString('Tag:', $rdata);
        $this->assertStringContainsString('Value:', $rdata);
    }
}
