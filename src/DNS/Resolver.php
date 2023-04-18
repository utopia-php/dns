<?php

namespace Utopia\DNS;

abstract class Resolver
{
    /**
     * Resolve DNS Record
     *
     * @param array<string, string> $question
     * @return string
     */
    abstract public function resolve(array $question): string;
}
