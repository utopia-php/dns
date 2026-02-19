<?php

namespace Tests\Unit\Utopia\DNS;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Exception\Message\DecodingException;
use Utopia\DNS\Exception\Message\PartialDecodingException;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Header;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Message\Question;

final class MessageTest extends TestCase
{
    public function testDecodeParsesStandardAnswer(): void
    {
        // Header: ID=0x1a2b, response, QD=1, AN=1, NS=0, AR=0 followed by question and single A answer
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
        // Same packet as above to ensure encode() round-trips original bytes
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

    public function testConstructorThrowsWhenQuestionCountMismatch(): void
    {
        $header = new Header(
            id: 0x1010,
            isResponse: false,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursionDesired: true,
            recursionAvailable: false,
            responseCode: Message::RCODE_NOERROR,
            questionCount: 2,
            answerCount: 0,
            authorityCount: 0,
            additionalCount: 0
        );

        $question = new Question('example.com', Record::TYPE_A);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid DNS response: question count mismatch');

        new Message($header, [$question]);
    }

    public function testConstructorThrowsWhenAnswerCountMismatch(): void
    {
        $header = new Header(
            id: 0x2020,
            isResponse: false,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursionDesired: true,
            recursionAvailable: false,
            responseCode: Message::RCODE_NOERROR,
            questionCount: 0,
            answerCount: 1,
            authorityCount: 0,
            additionalCount: 0
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid DNS response: answer count mismatch');

        new Message($header, []);
    }

    public function testConstructorThrowsWhenAuthorityCountMismatch(): void
    {
        $header = new Header(
            id: 0x3030,
            isResponse: false,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursionDesired: true,
            recursionAvailable: false,
            responseCode: Message::RCODE_NOERROR,
            questionCount: 0,
            answerCount: 0,
            authorityCount: 1,
            additionalCount: 0
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid DNS response: authority count mismatch');

        new Message($header, [], []);
    }

    public function testConstructorThrowsWhenAdditionalCountMismatch(): void
    {
        $header = new Header(
            id: 0x4040,
            isResponse: false,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursionDesired: true,
            recursionAvailable: false,
            responseCode: Message::RCODE_NOERROR,
            questionCount: 0,
            answerCount: 0,
            authorityCount: 0,
            additionalCount: 1
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid DNS response: additional count mismatch');

        new Message($header, [], [], []);
    }

    public function testDecodeThrowsForNxDomainWithoutAuthority(): void
    {
        // ID=0x1a2c, NXDOMAIN response with zero answers and zero authority -> should fail validation
        $message =
            "\x1a\x2c\x85\x83\x00\x01\x00\x00\x00\x00\x00\x00" .
            "\x07missing\x07example\x03com\x00\x00\x01\x00\x01";

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('NXDOMAIN requires SOA in authority');

        Message::decode($message);
    }

    public function testDecodeThrowsForNoDataWithoutAuthority(): void
    {
        // ID=0x1a2d, NOERROR response without SOA in authority -> should fail validation
        $message =
            "\x1a\x2d\x85\x80\x00\x01\x00\x00\x00\x00\x00\x00" .
            "\x05empty\x07example\x03com\x00\x00\x01\x00\x01";

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('NODATA should include SOA in authority');

        Message::decode($message);
    }

    public function testDecodeThrowsWhenPacketTooShort(): void
    {
        $packet = "\x00\x01\x00"; // shorter than 12-byte DNS header

        $this->expectException(DecodingException::class);
        $this->expectExceptionMessage('Invalid DNS response: header too short');

        Message::decode($packet);
    }

    public function testDecodeThrowsPartialDecodingOnTruncatedQuestion(): void
    {
        // Header declares 1 question but packet ends before QTYPE/QCLASS
        // Declares one question but omits QTYPE/QCLASS, causing question decode failure
        $packet =
            "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" .
            "\x03www\x07example\x03com\x00"; // missing type/class

        try {
            Message::decode($packet);
            $this->fail('Expected PartialDecodingException');
        } catch (PartialDecodingException $e) {
            $header = $e->getHeader();
            $this->assertSame(0x1234, $header->id);
            $this->assertSame(1, $header->questionCount);
            $this->assertSame('Question section truncated', $e->getMessage());
        }
    }

    public function testDecodeThrowsPartialDecodingOnTruncatedAnswer(): void
    {
        $question = "\x03www\x07example\x03com\x00\x00\x01\x00\x01"; // www.example.com IN A
        // Header: ID=0xabcd, QR=1, QD=1, AN=1
        $header = "\xab\xcd\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00";
        $answer =
            "\x03www\x07example\x03com\x00" .
            "\x00\x01" .
            "\x00\x01" .
            "\x00\x00\x01\x2C" .
            "\x00\x04"; // missing 4 bytes of RDATA entirely

        try {
            Message::decode($header . $question . $answer);
            $this->fail('Expected PartialDecodingException');
        } catch (PartialDecodingException $e) {
            $this->assertSame(0xABCD, $e->getHeader()->id);
            $this->assertSame('RDATA exceeds packet bounds', $e->getMessage());
        }
    }

    public function testDecodeThrowsPartialDecodingOnExtraBytes(): void
    {
        // Valid response with an extra trailing byte to trigger length validation
        $message =
            "\x1a\x2b\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" .
            "\x03www\x07example\x03com\x00\x00\x01\x00\x01" .
            "\x03www\x07example\x03com\x00" .
            "\x00\x01" .
            "\x00\x01" .
            "\x00\x00\x01\x2C" .
            "\x00\x04" .
            "\x5D\xB8\xD8\x22" .
            "\xFF"; // extra byte

        $this->expectException(PartialDecodingException::class);
        $this->expectExceptionMessage('Invalid packet length');

        Message::decode($message);
    }

    public function testDecodeNxDomainWithAuthority(): void
    {
        // SOA RDATA: ns1.example.com hostmaster.example.com 1 3600 900 604800 300
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
        $this->assertSame('ns1.example.com hostmaster.example.com 1 3600 900 604800 300', $soa->rdata);
    }

    /**
     * Tests RFC-compliant truncation behavior per RFC 1035 Section 6.2 and RFC 2181 Section 9.
     *
     * Truncation should:
     * 1. Work backward from the end (additional → authority → answers)
     * 2. Preserve as many complete answer RRSets as fit
     * 3. Only set TC flag when required data (answers) couldn't fully fit
     */
    public function testEncodeTruncatesWhenExceedingMaxSize(): void
    {
        $question = new Question('example.com', Record::TYPE_A);
        $query = Message::query($question, id: 0x1234);

        // Create a response with many answers that will exceed 512 bytes
        $answers = [];
        for ($i = 0; $i < 100; $i++) {
            $answers[] = new Record('example.com', Record::TYPE_A, Record::CLASS_IN, 60, '192.168.' . ($i % 256) . '.' . ($i % 256));
        }

        $response = Message::response(
            $query->header,
            Message::RCODE_NOERROR,
            questions: $query->questions,
            answers: $answers,
            authority: [],
            additional: []
        );

        // Encode with 512-byte limit (UDP max per RFC 1035)
        $truncated = $response->encode(512);
        $decoded = Message::decode($truncated);

        // Verify TC flag is set (RFC 2181 Section 9: TC set when answers couldn't fit)
        $this->assertTrue($decoded->header->truncated, 'TC flag should be set when answers are truncated');

        // RFC 1035 Section 6.2: Preserve as many complete answer records as fit
        $this->assertGreaterThan(0, count($decoded->answers), 'Should include answers that fit within size limit');
        $this->assertLessThan(100, count($decoded->answers), 'Not all answers should fit');

        // Verify other sections are cleared per RFC truncation order
        $this->assertCount(0, $decoded->authority, 'Authority should be cleared when truncated');
        $this->assertCount(0, $decoded->additional, 'Additional should be cleared when truncated');

        // Verify question is always preserved
        $this->assertCount(1, $decoded->questions);
        $this->assertSame($query->questions[0]->name, $decoded->questions[0]->name);

        // Verify truncated packet is within size limit
        $this->assertLessThanOrEqual(512, strlen($truncated));
    }

    /**
     * Tests that additional section is dropped first without setting TC flag.
     * Per RFC 2181 Section 9: TC should NOT be set merely because extra info couldn't fit.
     */
    public function testTruncationDropsAdditionalSectionFirst(): void
    {
        $question = new Question('example.com', Record::TYPE_MX);
        $query = Message::query($question, id: 0x5678);

        // Small answers that fit, but additional section pushes over limit
        $answers = [
            new Record('example.com', Record::TYPE_MX, Record::CLASS_IN, 300, 'mail.example.com', priority: 10),
        ];

        // Large additional section (glue records)
        $additional = [];
        for ($i = 0; $i < 50; $i++) {
            $additional[] = new Record('mail' . $i . '.example.com', Record::TYPE_A, Record::CLASS_IN, 300, '192.168.1.' . $i);
        }

        $response = Message::response(
            $query->header,
            Message::RCODE_NOERROR,
            questions: $query->questions,
            answers: $answers,
            authority: [],
            additional: $additional
        );

        $truncated = $response->encode(512);
        $decoded = Message::decode($truncated);

        // TC should NOT be set - answers fit, only additional was dropped
        $this->assertFalse($decoded->header->truncated, 'TC should NOT be set when only additional section is dropped');

        // Answers should be preserved
        $this->assertCount(1, $decoded->answers);
        $this->assertSame('example.com', $decoded->answers[0]->name);

        // Additional section should be dropped
        $this->assertCount(0, $decoded->additional);
    }

    /**
     * Tests that authority section is dropped after additional, before answers.
     */
    public function testTruncationDropsAuthoritySectionSecond(): void
    {
        $question = new Question('example.com', Record::TYPE_A);
        $query = Message::query($question, id: 0x9ABC);

        // Small answer that fits
        $answers = [
            new Record('example.com', Record::TYPE_A, Record::CLASS_IN, 60, '192.168.1.1'),
        ];

        // Authority section with NS records
        $authority = [];
        for ($i = 0; $i < 30; $i++) {
            $authority[] = new Record('example.com', Record::TYPE_NS, Record::CLASS_IN, 3600, 'ns' . $i . '.example.com');
        }

        $response = Message::response(
            $query->header,
            Message::RCODE_NOERROR,
            questions: $query->questions,
            answers: $answers,
            authority: $authority,
            additional: []
        );

        $truncated = $response->encode(512);
        $decoded = Message::decode($truncated);

        // TC should NOT be set - answers fit, only authority was dropped
        $this->assertFalse($decoded->header->truncated, 'TC should NOT be set when only authority section is dropped');

        // Answers should be preserved
        $this->assertCount(1, $decoded->answers);

        // Authority section should be dropped
        $this->assertCount(0, $decoded->authority);
    }

    public function testEncodeWithoutMaxSizeDoesNotTruncate(): void
    {
        $question = new Question('example.com', Record::TYPE_A);
        $query = Message::query($question, id: 0x1234);

        $answers = [];
        for ($i = 0; $i < 5; $i++) {
            $answers[] = new Record('example.com', Record::TYPE_A, Record::CLASS_IN, 60, '192.168.1.' . $i);
        }

        $response = Message::response(
            $query->header,
            Message::RCODE_NOERROR,
            questions: $query->questions,
            answers: $answers,
            authority: [],
            additional: []
        );

        // Encode without size limit
        $encoded = $response->encode();
        $decoded = Message::decode($encoded);

        // Verify TC flag is NOT set
        $this->assertFalse($decoded->header->truncated, 'TC flag should not be set on non-truncated response');

        // Verify all answers are preserved
        $this->assertCount(5, $decoded->answers);
    }

    /**
     * NODATA (NOERROR + no answers) with SOA in authority must be encodable when truncation
     * drops the authority section; we mark as non-authoritative to satisfy validation.
     */
    public function testEncodeNodataWithTruncationDroppingAuthority(): void
    {
        $question = new Question('empty.example.com', Record::TYPE_TXT);
        $query = Message::query($question, id: 0x1234);

        $soa = new Record(
            'example.com',
            Record::TYPE_SOA,
            Record::CLASS_IN,
            300,
            'ns.example.com. hostmaster.example.com. 2024010101 3600 600 86400 300'
        );

        $response = Message::response(
            $query->header,
            Message::RCODE_NOERROR,
            questions: $query->questions,
            answers: [],
            authority: [$soa],
            additional: [],
            authoritative: true
        );

        // Force truncation to drop authority (packet with question + SOA exceeds small limit)
        $truncated = $response->encode(80);
        $decoded = Message::decode($truncated);

        $this->assertCount(0, $decoded->answers);
        $this->assertCount(0, $decoded->authority);
        $this->assertFalse($decoded->header->authoritative, 'Dropped authority => non-authoritative');
    }
}
