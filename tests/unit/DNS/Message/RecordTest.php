<?php

namespace Tests\Unit\Utopia\DNS\Message;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Message\Record;

final class RecordTest extends TestCase
{
    public function testEncodeARecordMatchesBytes(): void
    {
        $record = new Record(
            name: 'example.com',
            type: Record::TYPE_A,
            class: Record::CLASS_IN,
            ttl: 300,
            rdata: '93.184.216.34'
        );

        $expected = "\x07example\x03com\x00"
            . "\x00\x01"
            . "\x00\x01"
            . "\x00\x00\x01\x2C"
            . "\x00\x04"
            . "\x5D\xB8\xD8\x22";

        $this->assertSame($expected, $record->encode());
    }

    public function testDecodeARecordParsesFields(): void
    {
        $data = "\x07example\x03com\x00"
            . "\x00\x01"
            . "\x00\x01"
            . "\x00\x00\x01\x2C"
            . "\x00\x04"
            . "\x5D\xB8\xD8\x22";

        $offset = 0;
        $record = Record::decode($data, $offset);

        $this->assertSame('example.com', $record->name);
        $this->assertSame(Record::TYPE_A, $record->type);
        $this->assertSame(Record::CLASS_IN, $record->class);
        $this->assertSame(300, $record->ttl);
        $this->assertSame('93.184.216.34', $record->rdata);
        $this->assertNull($record->priority);
        $this->assertNull($record->weight);
        $this->assertNull($record->port);
        $this->assertSame(strlen($data), $offset);
    }

    public function testEncodeMxRecordMatchesBytes(): void
    {
        $record = new Record(
            name: 'mail.example.com',
            type: Record::TYPE_MX,
            class: Record::CLASS_IN,
            ttl: 3600,
            rdata: 'mail.exchange.example.com',
            priority: 10
        );

        $expected = "\x04mail\x07example\x03com\x00"
            . "\x00\x0F"
            . "\x00\x01"
            . "\x00\x00\x0E\x10"
            . "\x00\x1D"
            . "\x00\x0A"
            . "\x04mail\x08exchange\x07example\x03com\x00";

        $this->assertSame($expected, $record->encode());
    }

    public function testDecodeMxRecordParsesFields(): void
    {
        $data = "\x04mail\x07example\x03com\x00"
            . "\x00\x0F"
            . "\x00\x01"
            . "\x00\x00\x0E\x10"
            . "\x00\x1D"
            . "\x00\x0A"
            . "\x04mail\x08exchange\x07example\x03com\x00";

        $offset = 0;
        $record = Record::decode($data, $offset);

        $this->assertSame('mail.example.com', $record->name);
        $this->assertSame(Record::TYPE_MX, $record->type);
        $this->assertSame(Record::CLASS_IN, $record->class);
        $this->assertSame(3600, $record->ttl);
        $this->assertSame(10, $record->priority);
        $this->assertSame('mail.exchange.example.com', $record->rdata);
        $this->assertSame(strlen($data), $offset);
    }

    public function testEncodeSrvRecordMatchesBytes(): void
    {
        $record = new Record(
            name: '_sip._tcp.example.com',
            type: Record::TYPE_SRV,
            class: Record::CLASS_IN,
            ttl: 7200,
            rdata: 'sip.example.com',
            priority: 5,
            weight: 10,
            port: 5060
        );

        $expected = "\x04_sip\x04_tcp\x07example\x03com\x00"
            . "\x00\x21"
            . "\x00\x01"
            . "\x00\x00\x1C\x20"
            . "\x00\x17"
            . "\x00\x05\x00\x0A\x13\xC4"
            . "\x03sip\x07example\x03com\x00";

        $this->assertSame($expected, $record->encode());
    }

    public function testDecodeSrvRecordParsesFields(): void
    {
        $data = "\x04_sip\x04_tcp\x07example\x03com\x00"
            . "\x00\x21"
            . "\x00\x01"
            . "\x00\x00\x1C\x20"
            . "\x00\x17"
            . "\x00\x05\x00\x0A\x13\xC4"
            . "\x03sip\x07example\x03com\x00";

        $offset = 0;
        $record = Record::decode($data, $offset);

        $this->assertSame('_sip._tcp.example.com', $record->name);
        $this->assertSame(Record::TYPE_SRV, $record->type);
        $this->assertSame(Record::CLASS_IN, $record->class);
        $this->assertSame(7200, $record->ttl);
        $this->assertSame(5, $record->priority);
        $this->assertSame(10, $record->weight);
        $this->assertSame(5060, $record->port);
        $this->assertSame('sip.example.com', $record->rdata);
        $this->assertSame(strlen($data), $offset);
    }

    public function testEncodeTxtRecordMatchesBytes(): void
    {
        $record = new Record(
            name: 'example.com',
            type: Record::TYPE_TXT,
            class: Record::CLASS_IN,
            ttl: 600,
            rdata: 'hello'
        );

        $expected = "\x07example\x03com\x00"
            . "\x00\x10"
            . "\x00\x01"
            . "\x00\x00\x02\x58"
            . "\x00\x06"
            . "\x05hello";

        $this->assertSame($expected, $record->encode());
    }

    public function testDecodeTxtRecordParsesFields(): void
    {
        $data = "\x07example\x03com\x00"
            . "\x00\x10"
            . "\x00\x01"
            . "\x00\x00\x02\x58"
            . "\x00\x06"
            . "\x05hello";

        $offset = 0;
        $record = Record::decode($data, $offset);

        $this->assertSame('example.com', $record->name);
        $this->assertSame(Record::TYPE_TXT, $record->type);
        $this->assertSame(Record::CLASS_IN, $record->class);
        $this->assertSame(600, $record->ttl);
        $this->assertSame('hello', $record->rdata);
        $this->assertSame(strlen($data), $offset);
    }

    public function testDecodeCnameRecordParsesNameRdata(): void
    {
        $data = "\x03www\x07example\x03com\x00"
            . "\x00\x05"
            . "\x00\x01"
            . "\x00\x00\x0F\xA0"
            . "\x00\x11"
            . "\x03cdn\x07example\x03com\x00";

        $offset = 0;
        $record = Record::decode($data, $offset);

        $this->assertSame('www.example.com', $record->name);
        $this->assertSame(Record::TYPE_CNAME, $record->type);
        $this->assertSame(Record::CLASS_IN, $record->class);
        $this->assertSame(4000, $record->ttl);
        $this->assertSame('cdn.example.com', $record->rdata);
        $this->assertSame(strlen($data), $offset);
    }

    public function testDecodeUnknownRecordKeepsHexData(): void
    {
        $data = "\x07example\x03com\x00"
            . "\xFE\xF8"
            . "\x00\x01"
            . "\x00\x00\x00\x3C"
            . "\x00\x02"
            . "\x0A\xFF";

        $offset = 0;
        $record = Record::decode($data, $offset);

        $this->assertSame('example.com', $record->name);
        $this->assertSame(0xFEF8, $record->type);
        $this->assertSame(Record::CLASS_IN, $record->class);
        $this->assertSame(60, $record->ttl);
        $this->assertSame('0aff', $record->rdata);
        $this->assertSame(strlen($data), $offset);
    }
}
