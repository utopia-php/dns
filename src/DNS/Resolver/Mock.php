<?php

namespace Utopia\DNS\Resolver;

use Utopia\DNS\Resolver;

class Mock extends Resolver
{   
    /**
     * Resolve DNS Record
     * 
     * @param string $domain
     * @param string $type
     * @param string $ip
     * @param int $port
     */
    public function resolve(string $domain, string $type, string $ip, int $port): string {
        return '127.0.0.1';
    }
}