<?php

namespace Utopia\DNS;

abstract class Resolver
{
    /**
     * Resolve DNS Record
     *
     * @param string $domain
     * @param string $type
     * @param string $ip
     * @param int $port
     */
    abstract public function resolve(string $domain, string $type, string $ip, int $port): string;
}
