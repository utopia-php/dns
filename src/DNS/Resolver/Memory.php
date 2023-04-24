<?php

namespace Utopia\DNS\Resolver;

use Utopia\DNS\Resolver;

class Memory extends Resolver
{
    /**
     * @var array<string, array<array<string, mixed>>> $records
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

        $this->records[$key][] = $answer;
    }

    /**
     * Resolve DNS Record
     *
     * @param array<string, string> $question
     * @return array<array<string, mixed>>
     */
    public function resolve(array $question): array
    {
        $key = $question['domain'] . '_' . $question['type'];

        if (\array_key_exists($key, $this->records)) {
            return $this->records[$key];
        } else {
            return [];
        }
    }
}
