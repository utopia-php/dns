<?php

namespace Utopia\DNS;

class Record
{
    public string $name;
    public int $ttl;
    public string $class;
    public string $type;
    public string $value;

    // Optional fields for MX/SRV
    public ?int $priority = null;
    public ?int $weight   = null;
    public ?int $port     = null;

    public function __construct(
        string $name,
        int $ttl,
        string $class,
        string $type,
        string $value
    ) {
        $this->name  = $name;
        $this->ttl   = $ttl;
        $this->class = $class;
        $this->type  = $type;
        $this->value = $value;
    }
}
