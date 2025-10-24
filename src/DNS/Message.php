<?php

namespace Utopia\DNS;

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

    public function __construct(
        public readonly Header $header,
        /** @var Question[] */
        public readonly array $questions = [],
        /** @var Record[] */
        public readonly array $answers = [],
        /** @var Record[] */
        public readonly array $authority = [],
        /** @var Record[] */
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
        if ($header->isResponse && !array_any($this->authority, fn ($record) => $record->type === Record::TYPE_SOA)) {
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
     * @param Message $query The query message to respond to.
     * @param int $responseCode The response code.
     * @param array<Record> $answers The answer records.
     * @param array<Record> $authority The authority records.
     * @param array<Record> $additional The additional records.
     * @param bool $authoritative Whether the response is authoritative.
     * @param bool $truncated Whether the response is truncated.
     * @param bool $recursionAvailable Whether recursion is available.
     * @return self The response message.
     */
    public static function response(
        Message $query,
        int $responseCode,
        array $answers = [],
        array $authority = [],
        array $additional = [],
        bool $authoritative = false,
        bool $truncated = false,
        bool $recursionAvailable = false
    ): self {
        $header = new Header(
            id: $query->header->id,
            isResponse: true,
            opcode: $query->header->opcode,
            authoritative: $authoritative,
            truncated: $truncated,
            recursionDesired: $query->header->recursionDesired,
            recursionAvailable: $recursionAvailable,
            responseCode: $responseCode,
            questionCount: count($query->questions),
            answerCount: count($answers),
            authorityCount: count($authority),
            additionalCount: count($additional)
        );

        return new self($header, $query->questions, $answers, $authority, $additional);
    }

    public static function decode(string $packet): self
    {
        if (strlen($packet) < Header::LENGTH) {
            throw new \InvalidArgumentException('Invalid DNS response: header too short');
        }

        // --- Parse header (12 bytes) ---
        $header = Header::decode($packet);

        // --- Parse Question Section ---
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
            throw new \InvalidArgumentException('Invalid packet length');
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
