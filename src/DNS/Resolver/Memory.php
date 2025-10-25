<?php

namespace Utopia\DNS\Resolver;

use Utopia\DNS\Message;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Resolver;

class Memory extends Resolver
{
    /**
     * @var array<string, array<int, list<Record>>> $records
     */
    protected array $records = [];

    /**
     * Add DNS Record
     */
    public function addRecord(Record $record): void
    {
        $nameKey = $this->normalizeNameKey($record->name);

        /** @var array<int, list<Record>> $recordsByName */
        $recordsByName = $this->records[$nameKey] ?? [];

        /** @var list<Record> $recordsByType */
        $recordsByType = $recordsByName[$record->type] ?? [];
        $recordsByType[] = $record;

        $recordsByName[$record->type] = $recordsByType;
        $this->records[$nameKey] = $recordsByName;
    }

    /**
     * Resolve DNS Record
     */
    public function resolve(Message $query): Message
    {
        if (empty($query->questions)) {
            throw new \InvalidArgumentException('Query must contain at least one question');
        }

        $question = $query->questions[0];
        $nameKey = $this->normalizeNameKey($question->name);

        $recordsByName = $this->records[$nameKey] ?? [];
        $answers = $recordsByName[$question->type] ?? [];

        if ($answers !== []) {
            $responseCode = Message::RCODE_NOERROR;
            $authority = [];
        } elseif ($recordsByName !== []) {
            $responseCode = Message::RCODE_NOERROR;
            $authority = $this->findSoaAuthority($question->name);
        } else {
            $responseCode = Message::RCODE_NXDOMAIN;
            $authority = $this->findSoaAuthority($question->name);
        }

        return Message::response($query, $responseCode, $answers, $authority, authoritative: true);
    }

    public function getName(): string
    {
        return 'memory';
    }

    /**
     * Attempt to locate the closest-matching SOA record for the queried domain.
     *
     * @return Record[]|array<int, Record>
     */
    private function findSoaAuthority(string $domain): array
    {
        $search = rtrim($domain, '.');
        $labels = $search === '' ? [] : explode('.', $search);

        while (!empty($labels)) {
            $candidate = implode('.', $labels);
            $candidateKey = $this->normalizeNameKey($candidate);

            /** @var array<int, list<Record>> $recordsByName */
            $recordsByName = $this->records[$candidateKey] ?? [];

            /** @var list<Record> $records */
            $records = $recordsByName[Record::TYPE_SOA] ?? [];

            if ($records !== []) {
                return $records;
            }

            array_shift($labels);
        }

        // Check apex (both empty string and @ are normalized to empty)
        $apexKey = $this->normalizeNameKey('');

        /** @var array<int, list<Record>> $apexRecordsByType */
        $apexRecordsByType = $this->records[$apexKey] ?? [];

        /** @var list<Record> $apexRecords */
        $apexRecords = $apexRecordsByType[Record::TYPE_SOA] ?? [];

        return $apexRecords;
    }

    /**
     * Normalize a DNS owner name to a canonical array key.
     * Both '@' and empty string normalize to empty (apex).
     */
    private function normalizeNameKey(string $name): string
    {
        $trimmed = rtrim($name, '.');

        if ($trimmed === '@' || $trimmed === '') {
            return '';
        }

        return strtolower($trimmed);
    }
}
