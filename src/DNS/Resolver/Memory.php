<?php

namespace Utopia\DNS\Resolver;

use Utopia\DNS\Resolver;
use Utopia\DNS\Record;

class Memory extends Resolver
{
    /**
     * @var array<string, array<int, Record>> $records
     */
    protected array $records = [];

    /**
     * Add DNS Record
     *
     * @param array<string, mixed> $answer
     * @return void
     */
    public function addRecord(string $domain, string $type, array $answer): void
    {
        $key = $domain . '_' . $type;

        if (!(\array_key_exists($key, $this->records))) {
            $this->records[$key] = [];
        }

        $this->records[$key][] = new Record(
            $domain,
            $answer['ttl'] ?? 1800,
            $answer['class'] ?? '',
            $type,
            $answer['value'] ?? ''
        );
    }

    /**
     * Resolve DNS Record
     *
     * @param array<string, string> $question
     * @return array<int, \Utopia\DNS\Record>
     */
    public function resolve(array $question): array
    {
        $key = $question['name'] . '_' . $question['type'];

        if (\array_key_exists($key, $this->records)) {
            return $this->records[$key];
        }

        return [];
    }

    /**
     * Get the name of the resolver
     *
     * @return string
     */
    public function getName(): string
    {
        return 'memory';
    }
}
