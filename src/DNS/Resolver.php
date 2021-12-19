<?php

namespace Utopia\DNS;

abstract class Resolver
{   
    /**
     * Resolve DNS Record
     * 
     * @param string $domain
     * @param string $type
     */
    abstract public function resolve(string $domain, string $type): string;
}