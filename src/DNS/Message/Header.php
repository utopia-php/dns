<?php

namespace Utopia\DNS\Message;

use Utopia\DNS\Exception\Message\DecodingException;

final readonly class Header
{
    public const int LENGTH = 12;

    public function __construct(
        public int $id,
        public bool $isResponse,
        public int $opcode,
        public bool $authoritative,
        public bool $truncated,
        public bool $recursionDesired,
        public bool $recursionAvailable,
        public int $responseCode,
        public int $questionCount,
        public int $answerCount,
        public int $authorityCount,
        public int $additionalCount
    ) {
        if ($opcode < 0 || $opcode > 15) {
            throw new DecodingException('Opcode must be 0-15');
        }
        if ($responseCode < 0 || $responseCode > 15) {
            throw new DecodingException('Response code must be 0-15');
        }
    }

    /**
     * Decode DNS header from wire format.
     *
     * Per RFC 1035 Section 4.1.1, the Z bits (bits 4-6 of the flags field)
     * MUST be zero. While the RFC says these bits should be ignored on
     * receipt, we validate them to detect malformed or malicious packets.
     *
     * @throws DecodingException if header is malformed or Z bits are non-zero
     */
    public static function decode(string $data, int $offset = 0): self
    {
        if (strlen($data) < $offset + self::LENGTH) {
            throw new DecodingException('DNS header too short');
        }

        $chunk = substr($data, $offset, self::LENGTH);
        $values = unpack('nid/nflags/nqdcount/nancount/nnscount/narcount', $chunk);

        if (
            !is_array($values)
            || !isset($values['id'], $values['flags'], $values['qdcount'], $values['ancount'], $values['nscount'], $values['arcount'])
            || !is_int($values['id'])
            || !is_int($values['flags'])
            || !is_int($values['qdcount'])
            || !is_int($values['ancount'])
            || !is_int($values['nscount'])
            || !is_int($values['arcount'])
        ) {
            throw new DecodingException('Failed to unpack DNS header');
        }

        $id = $values['id'];
        $flags = $values['flags'];
        $qdcount = $values['qdcount'];
        $ancount = $values['ancount'];
        $nscount = $values['nscount'];
        $arcount = $values['arcount'];

        // RFC 1035 Section 4.1.1: Z bits (bits 4-6) MUST be zero
        // Z bits are at positions 4, 5, 6 counting from bit 0 (rightmost)
        $zBits = ($flags >> 4) & 0x7;
        if ($zBits !== 0) {
            throw new DecodingException('Reserved Z bits must be zero per RFC 1035');
        }

        return new self(
            id: $id,
            isResponse: (bool) (($flags >> 15) & 0x1),
            opcode: ($flags >> 11) & 0xF,
            authoritative: (bool) (($flags >> 10) & 0x1),
            truncated: (bool) (($flags >> 9) & 0x1),
            recursionDesired: (bool) (($flags >> 8) & 0x1),
            recursionAvailable: (bool) (($flags >> 7) & 0x1),
            responseCode: $flags & 0xF,
            questionCount: $qdcount,
            answerCount: $ancount,
            authorityCount: $nscount,
            additionalCount: $arcount
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
