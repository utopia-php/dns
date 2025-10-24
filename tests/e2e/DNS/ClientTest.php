<?php

namespace Tests\Utopia\DNS;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Client;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;

final class ClientTest extends TestCase
{
    public const int PORT = 54;

    public function testARecords(): void
    {
        $client = new Client('localhost', self::PORT);
        $response = $client->query(new Question('dev.appwrite.io', Record::TYPE_A));
        $records = $response->answers;

        $this->assertCount(1, $records);
        $this->assertInstanceOf(Record::class, $records[0]);
        $this->assertSame('dev.appwrite.io', $records[0]->name);
        $this->assertSame(Record::CLASS_IN, $records[0]->class);
        $this->assertSame(10, $records[0]->ttl);
        $this->assertSame(Record::TYPE_A, $records[0]->type);
        $this->assertSame('180.12.3.24', $records[0]->rdata);

        $response = $client->query(new Question('dev2.appwrite.io', Record::TYPE_A));
        $records = $response->answers;

        $this->assertCount(2, $records);
        $this->assertSame('dev2.appwrite.io', $records[0]->name);
        $this->assertSame(Record::CLASS_IN, $records[0]->class);
        $this->assertSame(1800, $records[0]->ttl);
        $this->assertSame(Record::TYPE_A, $records[0]->type);
        $this->assertSame('142.6.0.1', $records[0]->rdata);
        $this->assertSame('142.6.0.2', $records[1]->rdata);

        $response = $client->query(new Question('dev3.appwrite.io', Record::TYPE_A));
        $this->assertCount(0, $response->answers);
    }

    public function testAAAARecords(): void
    {
        $client = new Client('localhost', self::PORT);
        $response = $client->query(new Question('dev.appwrite.io', Record::TYPE_AAAA));
        $records = $response->answers;

        $this->assertCount(1, $records);
        $this->assertSame('dev.appwrite.io', $records[0]->name);
        $this->assertSame(Record::CLASS_IN, $records[0]->class);
        $this->assertSame(20, $records[0]->ttl);
        $this->assertSame(Record::TYPE_AAAA, $records[0]->type);
        $this->assertSame('2001:db8::ff00:42:8329', $records[0]->rdata);

        $response = $client->query(new Question('dev2.appwrite.io', Record::TYPE_AAAA));
        $records = $response->answers;

        $this->assertCount(2, $records);
        $this->assertSame('2001:db8::ff00:0:1', $records[0]->rdata);
        $this->assertSame('2001:db8::ff00:0:2', $records[1]->rdata);

        $response = $client->query(new Question('dev3.appwrite.io', Record::TYPE_AAAA));
        $this->assertCount(0, $response->answers);
    }

    public function testCnameRecords(): void
    {
        $client = new Client('localhost', self::PORT);
        $response = $client->query(new Question('alias.appwrite.io', Record::TYPE_CNAME));
        $records = $response->answers;

        $this->assertCount(1, $records);
        $this->assertSame('alias.appwrite.io', $records[0]->name);
        $this->assertSame(Record::CLASS_IN, $records[0]->class);
        $this->assertSame(30, $records[0]->ttl);
        $this->assertSame(Record::TYPE_CNAME, $records[0]->type);
        $this->assertSame('cloud.appwrite.io', $records[0]->rdata);

        $response = $client->query(new Question('alias-eu.appwrite.io', Record::TYPE_CNAME));
        $records = $response->answers;

        $this->assertCount(1, $records);
        $this->assertSame('alias-eu.appwrite.io', $records[0]->name);
        $this->assertSame(Record::CLASS_IN, $records[0]->class);
        $this->assertSame(Record::TYPE_CNAME, $records[0]->type);
        $this->assertSame('eu.cloud.appwrite.io', $records[0]->rdata);

        $response = $client->query(new Question('alias-us.appwrite.io', Record::TYPE_CNAME));
        $records = $response->answers;

        $this->assertCount(1, $records);
        $this->assertSame('alias-us.appwrite.io', $records[0]->name);
        $this->assertSame(Record::CLASS_IN, $records[0]->class);
        $this->assertSame(Record::TYPE_CNAME, $records[0]->type);
        $this->assertSame('us.cloud.appwrite.io', $records[0]->rdata);

        $response = $client->query(new Question('dev3.appwrite.io', Record::TYPE_CNAME));
        $this->assertCount(0, $response->answers);
    }

    public function testTxtRecords(): void
    {
        $client = new Client('localhost', self::PORT);
        $response = $client->query(new Question('dev.appwrite.io', Record::TYPE_TXT));
        $records = $response->answers;

        $this->assertCount(1, $records);
        $this->assertSame('dev.appwrite.io', $records[0]->name);
        $this->assertSame(Record::CLASS_IN, $records[0]->class);
        $this->assertSame(40, $records[0]->ttl);
        $this->assertSame(Record::TYPE_TXT, $records[0]->type);
        $this->assertSame('awesome-secret-key', $records[0]->rdata);

        $response = $client->query(new Question('dev2.appwrite.io', Record::TYPE_TXT));
        $records = $response->answers;

        $this->assertCount(3, $records);
        $this->assertSame('key with "$\'- symbols', $records[0]->rdata);
        $this->assertSame('key with spaces', $records[1]->rdata);
        $this->assertSame('v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1;', $records[2]->rdata);

        $response = $client->query(new Question('dev3.appwrite.io', Record::TYPE_TXT));
        $this->assertCount(0, $response->answers);
    }

    public function testNsRecords(): void
    {
        $client = new Client('localhost', self::PORT);
        $response = $client->query(new Question('dev.appwrite.io', Record::TYPE_NS));
        $records = $response->answers;

        $this->assertCount(1, $records);
        $this->assertSame('dev.appwrite.io', $records[0]->name);
        $this->assertSame(Record::CLASS_IN, $records[0]->class);
        $this->assertSame(60, $records[0]->ttl);
        $this->assertSame(Record::TYPE_NS, $records[0]->type);
        $this->assertSame('ns.appwrite.io', $records[0]->rdata);

        $response = $client->query(new Question('dev2.appwrite.io', Record::TYPE_NS));
        $records = $response->answers;

        $this->assertCount(2, $records);
        $this->assertSame('ns1.appwrite.io', $records[0]->rdata);
        $this->assertSame('ns2.appwrite.io', $records[1]->rdata);

        $response = $client->query(new Question('dev3.appwrite.io', Record::TYPE_NS));
        $this->assertCount(0, $response->answers);
    }

    public function testCaaRecords(): void
    {
        $client = new Client('localhost', self::PORT);
        $response = $client->query(new Question('dev.appwrite.io', Record::TYPE_CAA));
        $records = $response->answers;

        $this->assertCount(1, $records);
        $this->assertSame('dev.appwrite.io', $records[0]->name);
        $this->assertSame(Record::CLASS_IN, $records[0]->class);
        $this->assertSame(Record::TYPE_CAA, $records[0]->type);

        $this->assertSame('0 issue "letsencrypt.org"', $records[0]->rdata);

        $response = $client->query(new Question('dev2.appwrite.io', Record::TYPE_CAA));
        $records = $response->answers;

        $this->assertCount(2, $records);
        $this->assertSame('0 issue "letsencrypt.org"', $records[0]->rdata);
        $this->assertSame('0 issue "sectigo.com"', $records[1]->rdata);

        $response = $client->query(new Question('dev3.appwrite.io', Record::TYPE_CAA));
        $records = $response->answers;

        $this->assertCount(1, $records);
        $this->assertSame('255 issuewild "certainly.com;validationmethods=tls-alpn-01;retrytimeout=3600"', $records[0]->rdata);
    }

    public function testSoaRecords(): void
    {
        $client = new Client('localhost', self::PORT);
        $response = $client->query(new Question('appwrite.io', Record::TYPE_SOA));
        $records = $response->answers;

        $this->assertCount(1, $records);
        $this->assertSame('appwrite.io', $records[0]->name);
        $this->assertSame(Record::CLASS_IN, $records[0]->class);
        $this->assertSame(3600, $records[0]->ttl);
        $this->assertSame(Record::TYPE_SOA, $records[0]->type);

        $rdata = $records[0]->rdata;
        $this->assertStringContainsString('ns1.appwrite.io.', $rdata);
        $this->assertStringContainsString('admin.appwrite.io.', $rdata);
        $this->assertStringContainsString('2025011801', $rdata);

        $response = $client->query(new Question('dev2.appwrite.io', Record::TYPE_SOA));
        $answers = $response->answers;
        $this->assertCount(0, $answers);

        $authority = $response->authority;
        $this->assertCount(1, $authority);
        $this->assertSame('appwrite.io', $authority[0]->name);

        $rdata = $authority[0]->rdata;
        $this->assertStringContainsString('ns1.appwrite.io.', $rdata);
        $this->assertStringContainsString('admin.appwrite.io.', $rdata);
        $this->assertStringContainsString('2025011801', $rdata);
    }
}
