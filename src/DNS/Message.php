<?php

namespace Utopia\DNS;

use Utopia\DNS\Exception\Message\DecodingException;
use Utopia\DNS\Exception\Message\PartialDecodingException;
use Utopia\DNS\Message\Header;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;

final class Message
{
    public const int RCODE_NOERROR = 0;
    public const int RCODE_FORMERR = 1;
    public const int RCODE_SERVFAIL = 2;
    public const int RCODE_NXDOMAIN = 3;
    public const int RCODE_NOTIMP = 4;
    public const int RCODE_REFUSED = 5;
    public const int RCODE_YXDOMAIN = 6;
    public const int RCODE_YXRRSET = 7;
    public const int RCODE_NXRRSET = 8;
    public const int RCODE_NOTAUTH = 9;
    public const int RCODE_NOTZONE = 10;

    /**
     * @param Header $header The header of the message.
     * @param Question[] $questions The question records.
     * @param list<Record> $answers The answer records.
     * @param list<Record> $authority The authority records.
     * @param list<Record> $additional The additional records.
     */
    public function __construct(
        public readonly Header $header,
        /** @var Question[] */
        public readonly array $questions = [],
        /** @var list<Record> */
        public readonly array $answers = [],
        /** @var list<Record> */
        public readonly array $authority = [],
        /** @var list<Record> */
        public readonly array $additional = []
    ) {
        if ($header->questionCount !== count($questions)) {
            throw new \InvalidArgumentException('Invalid DNS response: question count mismatch');
        }
        if ($header->answerCount !== count($answers)) {
            throw new \InvalidArgumentException('Invalid DNS response: answer count mismatch');
        }
        if ($header->authorityCount !== count($authority)) {
            throw new \InvalidArgumentException('Invalid DNS response: authority count mismatch');
        }
        if ($header->additionalCount !== count($additional)) {
            throw new \InvalidArgumentException('Invalid DNS response: additional count mismatch');
        }
        $soaAuthorityCount = count(array_filter(
            $this->authority,
            fn ($record) => $record->type === Record::TYPE_SOA
        ));

        if ($header->isResponse && $header->authoritative && $soaAuthorityCount < 1) {
            if ($header->responseCode === self::RCODE_NXDOMAIN) {
                throw new \InvalidArgumentException('NXDOMAIN requires SOA in authority');
            }
            if ($header->responseCode === self::RCODE_NOERROR && $answers === []) {
                throw new \InvalidArgumentException('NODATA should include SOA in authority');
            }
        }
    }

    public static function query(
        Question $question,
        ?int $id = null,
        bool $recursionDesired = true
    ): self {
        if ($id === null) {
            $id = random_int(0, 0xFFFF);
        }

        $header = new Header(
            id: $id,
            isResponse: false,
            opcode: 0, // QUERY
            authoritative: false,
            truncated: false,
            recursionDesired: $recursionDesired,
            recursionAvailable: false,
            responseCode: 0,
            questionCount: 1,
            answerCount: 0,
            authorityCount: 0,
            additionalCount: 0
        );

        return new self($header, [$question]);
    }

    /**
     * Create a response message.
     *
     * @param Header $header The header of the query message to respond to.
     * @param int $responseCode The response code.
     * @param array<Question> $questions The question records.
     * @param list<Record> $answers The answer records.
     * @param list<Record> $authority The authority records.
     * @param list<Record> $additional The additional records.
     * @param bool $authoritative Whether the response is authoritative.
     * @param bool $truncated Whether the response is truncated.
     * @param bool $recursionAvailable Whether recursion is available.
     * @return self The response message.
     */
    public static function response(
        Header $header,
        int $responseCode,
        array $questions = [],
        array $answers = [],
        array $authority = [],
        array $additional = [],
        bool $authoritative = false,
        bool $truncated = false,
        bool $recursionAvailable = false
    ): self {
        $header = new Header(
            id: $header->id,
            isResponse: true,
            opcode: $header->opcode,
            authoritative: $authoritative,
            truncated: $truncated,
            recursionDesired: $header->recursionDesired,
            recursionAvailable: $recursionAvailable,
            responseCode: $responseCode,
            questionCount: count($questions),
            answerCount: count($answers),
            authorityCount: count($authority),
            additionalCount: count($additional)
        );


        return new self($header, $questions, $answers, $authority, $additional);
    }

    public static function decode(string $packet): self
    {
        if (strlen($packet) < Header::LENGTH) {
            throw new DecodingException('Invalid DNS response: header too short');
        }

        // --- Parse header (12 bytes) ---
        $header = Header::decode($packet);

        // --- Parse Question Section ---
        try {
            $offset = Header::LENGTH;
            $questions = [];
            for ($i = 0; $i < $header->questionCount; $i++) {
                $questions[] = Question::decode($packet, $offset);
            }

            // --- Decode Answer Section ---
            $answers = [];
            for ($i = 0; $i < $header->answerCount; $i++) {
                $answers[] = Record::decode($packet, $offset);
            }

            // --- Decode Authority Section ---
            $authority = [];
            for ($i = 0; $i < $header->authorityCount; $i++) {
                $authority[] = Record::decode($packet, $offset);
            }

            // --- Decode Additional Section ---
            $additional = [];
            for ($i = 0; $i < $header->additionalCount; $i++) {
                $additional[] = Record::decode($packet, $offset);
            }

            if ($offset !== strlen($packet)) {
                throw new DecodingException('Invalid packet length');
            }
        } catch (DecodingException $e) {
            throw new PartialDecodingException($header, $e->getMessage(), $e);
        }

        return new self($header, $questions, $answers, $authority, $additional);
    }

    public function encode(): string
    {
        $packet = $this->header->encode();

        foreach ($this->questions as $question) {
            $packet .= $question->encode();
        }

        foreach ($this->answers as $answer) {
            $packet .= $answer->encode($packet);
        }

        foreach ($this->authority as $authority) {
            $packet .= $authority->encode($packet);
        }

        foreach ($this->additional as $additional) {
            $packet .= $additional->encode($packet);
        }

        return $packet;
    }
}
