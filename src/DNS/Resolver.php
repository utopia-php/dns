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

    /**
     * Get the name of the resolver
     * 
     * @return string
     */
    abstract public function getName(): string;
}
