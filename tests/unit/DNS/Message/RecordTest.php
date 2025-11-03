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

        // Raw RR: example.com. 300 IN A 93.184.216.34
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
        // Raw RR: example.com. 300 IN A 93.184.216.34
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

        // Raw RR: mail.example.com. 3600 IN MX 10 mail.exchange.example.com.
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
        // Raw RR: mail.example.com. 3600 IN MX 10 mail.exchange.example.com.
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

        // Raw RR: _sip._tcp.example.com. 7200 IN SRV 5 10 5060 sip.example.com.
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
        // Raw RR: _sip._tcp.example.com. 7200 IN SRV 5 10 5060 sip.example.com.
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

        // Raw RR: example.com. 600 IN TXT "hello"
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
        // Raw RR: example.com. 600 IN TXT "hello"
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
        // Raw RR: www.example.com. 4000 IN CNAME cdn.example.com.
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
        // Raw RR: example.com. 60 IN TYPE65400 RDATA=0x0aff
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

    public function testDecodeSoaRecordParsesFields(): void
    {
        // Raw RR: example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024102701 7200 3600 1209600 86400
        $data = "\x07example\x03com\x00"
            . "\x00\x06"  // TYPE_SOA
            . "\x00\x01"  // CLASS_IN
            . "\x00\x00\x0E\x10"  // TTL: 3600
            . "\x00\x38"  // RDLENGTH: 56 bytes (17 + 19 + 20)
            // MNAME: ns1.example.com (17 bytes)
            . "\x03ns1\x07example\x03com\x00"
            // RNAME: admin.example.com (19 bytes)
            . "\x05admin\x07example\x03com\x00"
            // Serial: 2024102701 = 0x78a55b2d
            . "\x78\xa5\x5b\x2d"
            // Refresh: 7200
            . "\x00\x00\x1C\x20"
            // Retry: 3600
            . "\x00\x00\x0E\x10"
            // Expire: 1209600
            . "\x00\x12\x75\x00"
            // Minimum: 86400
            . "\x00\x01\x51\x80";

        $offset = 0;
        $record = Record::decode($data, $offset);

        $this->assertSame('example.com', $record->name);
        $this->assertSame(Record::TYPE_SOA, $record->type);
        $this->assertSame(Record::CLASS_IN, $record->class);
        $this->assertSame(3600, $record->ttl);
        $this->assertSame(
            'ns1.example.com admin.example.com 2024102701 7200 3600 1209600 86400',
            $record->rdata
        );
        $this->assertSame(strlen($data), $offset);
    }

    public function testEncodeSoaRecordMatchesBytes(): void
    {
        $record = new Record(
            name: 'example.com',
            type: Record::TYPE_SOA,
            class: Record::CLASS_IN,
            ttl: 3600,
            rdata: 'ns1.example.com admin.example.com 2024102701 7200 3600 1209600 86400'
        );

        $expected = "\x07example\x03com\x00"
            . "\x00\x06"
            . "\x00\x01"
            . "\x00\x00\x0E\x10"
            . "\x00\x38"  // RDLENGTH: 56 bytes
            . "\x03ns1\x07example\x03com\x00"
            . "\x05admin\x07example\x03com\x00"
            . "\x78\xa5\x5b\x2d"
            . "\x00\x00\x1C\x20"
            . "\x00\x00\x0E\x10"
            . "\x00\x12\x75\x00"
            . "\x00\x01\x51\x80";

        $this->assertSame($expected, $record->encode());
    }

    public function testDecodeTxtRecordWithMultipleChunks(): void
    {
        // TXT with two chunks: "hello" (5 bytes) + "world" (5 bytes)
        $data = "\x07example\x03com\x00"
            . "\x00\x10"  // TYPE_TXT
            . "\x00\x01"  // CLASS_IN
            . "\x00\x00\x02\x58"  // TTL: 600
            . "\x00\x0C"  // RDLENGTH: 12 bytes (1+5+1+5)
            . "\x05hello"
            . "\x05world";

        $offset = 0;
        $record = Record::decode($data, $offset);

        $this->assertSame('example.com', $record->name);
        $this->assertSame(Record::TYPE_TXT, $record->type);
        $this->assertSame(Record::CLASS_IN, $record->class);
        $this->assertSame(600, $record->ttl);
        $this->assertSame('helloworld', $record->rdata);
        $this->assertSame(strlen($data), $offset);
    }

    public function testDecodeTxtRecordWithThreeChunks(): void
    {
        // TXT with three chunks: 1+3 + 1+3 + 1+3 = 12 bytes
        $data = "\x07example\x03com\x00"
            . "\x00\x10"
            . "\x00\x01"
            . "\x00\x00\x02\x58"
            . "\x00\x0C"  // RDLENGTH: 12 bytes (not 15)
            . "\x03foo"
            . "\x03bar"
            . "\x03baz";

        $offset = 0;
        $record = Record::decode($data, $offset);

        $this->assertSame('foobarbaz', $record->rdata);
    }

    public function testDecodeSoaRecordRoundTrip(): void
    {
        // Original SOA RR for round-trip comparison: example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024102701 7200 3600 1209600 86400
        $original = "\x07example\x03com\x00"
            . "\x00\x06"
            . "\x00\x01"
            . "\x00\x00\x0E\x10"
            . "\x00\x38"  // RDLENGTH: 56 bytes
            . "\x03ns1\x07example\x03com\x00"
            . "\x05admin\x07example\x03com\x00"
            . "\x78\xa5\x5b\x2d"
            . "\x00\x00\x1C\x20"
            . "\x00\x00\x0E\x10"
            . "\x00\x12\x75\x00"
            . "\x00\x01\x51\x80";

        $offset = 0;
        $record = Record::decode($original, $offset);
        $encoded = $record->encode();

        $this->assertSame($original, $encoded);
    }
}
