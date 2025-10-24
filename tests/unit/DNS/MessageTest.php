<?php

namespace Tests\Unit\Utopia\DNS;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Record;

final class MessageTest extends TestCase
{
    public function testDecodeParsesStandardAnswer(): void
    {
        $message =
            "\x1a\x2b\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" .
            "\x03www\x07example\x03com\x00\x00\x01\x00\x01" .
            "\x03www\x07example\x03com\x00" .
            "\x00\x01" .
            "\x00\x01" .
            "\x00\x00\x01\x2C" .
            "\x00\x04" .
            "\x5D\xB8\xD8\x22";

        $response = Message::decode($message);

        $this->assertSame(Message::RCODE_NOERROR, $response->header->responseCode);
        $this->assertNotEmpty($response->questions);
        $question = $response->questions[0];
        $this->assertSame('www.example.com', $question->name);
        $this->assertSame(Record::TYPE_A, $question->type);
        $this->assertSame(Record::CLASS_IN, $question->class);

        $this->assertCount(1, $response->answers);
        $answer = $response->answers[0];
        $this->assertSame('www.example.com', $answer->name);
        $this->assertSame(Record::TYPE_A, $answer->type);
        $this->assertSame(Record::CLASS_IN, $answer->class);
        $this->assertSame(300, $answer->ttl);
        $this->assertSame('93.184.216.34', $answer->rdata);
        $this->assertNull($answer->priority);
        $this->assertNull($answer->weight);
        $this->assertNull($answer->port);

        $this->assertSame([], $response->authority);
        $this->assertSame([], $response->additional);
    }

    public function testEncodeProducesOriginalBytes(): void
    {
        $message =
            "\x1a\x2b\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" .
            "\x03www\x07example\x03com\x00\x00\x01\x00\x01" .
            "\x03www\x07example\x03com\x00" .
            "\x00\x01" .
            "\x00\x01" .
            "\x00\x00\x01\x2C" .
            "\x00\x04" .
            "\x5D\xB8\xD8\x22";

        $response = Message::decode($message);
        $encoded = $response->encode();
        $this->assertSame($message, $encoded);
    }

    public function testDecodeThrowsForNxDomainWithoutAuthority(): void
    {
        $message =
            "\x1a\x2c\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" .
            "\x07missing\x07example\x03com\x00\x00\x01\x00\x01";

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('NXDOMAIN requires SOA in authority');

        Message::decode($message);
    }

    public function testDecodeThrowsForNoDataWithoutAuthority(): void
    {
        $message =
            "\x1a\x2d\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" .
            "\x05empty\x07example\x03com\x00\x00\x01\x00\x01";

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('NODATA should include SOA in authority');

        Message::decode($message);
    }

    public function testDecodeNxDomainWithAuthority(): void
    {
        $authorityRdata =
            "\x03ns1\x07example\x03com\x00" .
            "\x0Ahostmaster\x07example\x03com\x00" .
            "\x00\x00\x00\x01" .
            "\x00\x00\x0E\x10" .
            "\x00\x00\x03\x84" .
            "\x00\x09\x3A\x80" .
            "\x00\x00\x01\x2C";

        $message =
            "\x1a\x2e\x81\x83\x00\x01\x00\x00\x00\x01\x00\x00" .
            "\x07missing\x07example\x03com\x00\x00\x01\x00\x01" .
            "\x07example\x03com\x00" .
            "\x00\x06" .
            "\x00\x01" .
            "\x00\x00\x03\x84" .
            "\x00\x3D" .
            $authorityRdata;

        $response = Message::decode($message);

        $this->assertSame(Message::RCODE_NXDOMAIN, $response->header->responseCode);
        $this->assertCount(1, $response->authority);
        $soa = $response->authority[0];
        $this->assertSame('example.com', $soa->name);
        $this->assertSame(Record::TYPE_SOA, $soa->type);
        $this->assertSame(Record::CLASS_IN, $soa->class);
        $this->assertSame(900, $soa->ttl);
        $this->assertSame('ns1.example.com. hostmaster.example.com. 1 3600 900 604800 300', $soa->rdata);
    }
}
