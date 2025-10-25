<?php

namespace Utopia\DNS\Message;

final class Header
{
    public const int LENGTH = 12;

    public function __construct(
        public readonly int $id,
        public readonly bool $isResponse,
        public readonly int $opcode,
        public readonly bool $authoritative,
        public readonly bool $truncated,
        public readonly bool $recursionDesired,
        public readonly bool $recursionAvailable,
        public readonly int $responseCode,
        public readonly int $questionCount,
        public readonly int $answerCount,
        public readonly int $authorityCount,
        public readonly int $additionalCount
    ) {
        if ($opcode < 0 || $opcode > 15) {
            throw new \InvalidArgumentException('Opcode must be 0-15');
        }
        if ($responseCode < 0 || $responseCode > 15) {
            throw new \InvalidArgumentException('Response code must be 0-15');
        }
    }

    public static function decode(string $data, int $offset = 0): self
    {
        if (strlen($data) < $offset + self::LENGTH) {
            throw new \InvalidArgumentException('DNS header too short');
        }

        $chunk = substr($data, $offset, self::LENGTH);
        $values = unpack('nid/nflags/nqdcount/nancount/nnscount/narcount', $chunk);

        if (!is_array($values)) {
            throw new \RuntimeException('Failed to unpack DNS header');
        }

        $flags = $values['flags'];

        return new self(
            id: $values['id'],
            isResponse: (bool) (($flags >> 15) & 0x1),
            opcode: ($flags >> 11) & 0xF,
            authoritative: (bool) (($flags >> 10) & 0x1),
            truncated: (bool) (($flags >> 9) & 0x1),
            recursionDesired: (bool) (($flags >> 8) & 0x1),
            recursionAvailable: (bool) (($flags >> 7) & 0x1),
            responseCode: $flags & 0xF,
            questionCount: $values['qdcount'],
            answerCount: $values['ancount'],
            authorityCount: $values['nscount'],
            additionalCount: $values['arcount']
        );
    }

    public function encode(): string
    {
        $flags =
            ($this->isResponse ? 1 : 0) << 15 |
            ($this->opcode & 0xF) << 11 |
            ($this->authoritative ? 1 : 0) << 10 |
            ($this->truncated ? 1 : 0) << 9 |
            ($this->recursionDesired ? 1 : 0) << 8 |
            ($this->recursionAvailable ? 1 : 0) << 7 |
            ($this->responseCode & 0xF);

        return pack(
            'nnnnnn',
            $this->id,
            $flags,
            $this->questionCount,
            $this->answerCount,
            $this->authorityCount,
            $this->additionalCount
        );
    }
}
