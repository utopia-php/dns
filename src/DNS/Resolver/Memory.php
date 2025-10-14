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

        // Special handling for SOA records: if not found at the exact domain,
        // walk up the domain hierarchy to find the zone apex SOA record
        if ($question['type'] === 'SOA') {
            $domain = $question['name'];
            $parts = explode('.', $domain);

            // Try each parent domain level, starting from immediate parent
            // e.g., for "dev.sub.example.com", try "sub.example.com", then "example.com"
            while (count($parts) > 1) {
                array_shift($parts); // Remove leftmost subdomain
                $parentDomain = implode('.', $parts);
                $parentKey = $parentDomain . '_SOA';

                if (\array_key_exists($parentKey, $this->records)) {
                    return $this->records[$parentKey];
                }
            }
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
