<?php

namespace Utopia\DNS\Resolver;

use Utopia\DNS\Resolver;

class Mock extends Resolver
{
    /**
     * Resolve DNS Record
     *
     * @param array<string, string> $question
     * @return string
     */
    public function resolve(array $question): string
    {
        return '127.0.0.1';
    }
}
