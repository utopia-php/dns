<?php

namespace Utopia\DNS\Resolver;

use Utopia\DNS\Resolver;

class Mock extends Resolver
{
    /**
     * Resolve DNS Record
     *
     * @param array<string, string> $question
     * @return array<array<string, mixed>>
     */
    public function resolve(array $question): array
    {
        $type = $question['type'];

        if ($type === 'A') {
            return [
                [
                    'value' => '180.12.3.24',
                    'ttl' => 600
                ]
            ];
        } elseif ($type === 'AAAA') {
            return [
                [
                    'value' => '2001:0db8:0000:0000:0000:ff00:0042:8329',
                    'ttl' => 1800
                ]
            ];
        } elseif ($type === 'CNAME') {
            return [
                [
                    'value' => 'appwrite.io',
                    'ttl' => 1800
                ]
            ];
        } elseif ($type === 'TXT') {
            return [
                [
                    'value' => 'myCustomValue',
                    'ttl' => 1800
                ]
            ];
        } elseif ($type === 'SRV') {
            return [
                [
                    'value' => 'server.appwrite.io',
                    'ttl' => 1800,
                    'priority' => 10,
                    'weight' => 5,
                    'port' => 25565
                ]
            ];
        } elseif ($type === 'MX') {
            return [
                [
                    'value' => 'mx.appwrite.io',
                    'ttl' => 1800,
                    'priority' => 10
                ]
            ];
        } elseif ($type === 'NS') {
            return [
                [
                    'value' => 'ns.appwrite.io',
                    'ttl' => 1800,
                ]
            ];
        } elseif ($type === 'CAA') {
            return [
                [
                    'value' => 'issue "letsencrypt.org"',
                    'ttl' => 1800,
                ]
            ];
        }

        return [];
    }
}
