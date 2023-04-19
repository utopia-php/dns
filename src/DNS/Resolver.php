<?php

namespace Utopia\DNS;

abstract class Resolver
{
    /**
     * Resolve DNS Record
     *
     * @param array<string, string> $question
     * @return array<array<string, mixed>>
     */
    abstract public function resolve(array $question): array;
}
