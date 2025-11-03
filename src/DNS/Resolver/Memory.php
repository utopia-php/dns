<?php

namespace Utopia\DNS\Resolver;

use Utopia\DNS\Message;
use Utopia\DNS\Resolver;
use Utopia\DNS\Zone;
use Utopia\DNS\Zone\Resolver as ZoneResolver;

class Memory implements Resolver
{
    public function __construct(private readonly Zone $zone)
    {
    }

    public function resolve(Message $query): Message
    {
        return ZoneResolver::lookup($query, $this->zone);
    }

    public function getName(): string
    {
        return 'memory';
    }
}
