<?php

namespace Utopia\DNS\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Record;

final class RecordTest extends TestCase
{
    public function testConstructorAndDefaults(): void
    {
        $record = new Record('www', 3600, 'IN', 'A', '127.0.0.1');

        $this->assertSame('www', $record->name);
        $this->assertSame(3600, $record->ttl);
        $this->assertSame('IN', $record->class);
        $this->assertSame('A', $record->type);
        $this->assertSame('127.0.0.1', $record->value);

        // Optional fields should be null by default
        $this->assertNull($record->priority);
        $this->assertNull($record->weight);
        $this->assertNull($record->port);
    }

    public function testSetPriorityForMX(): void
    {
        $record = new Record('mail', 3600, 'IN', 'MX', 'mail.example.com');
        $record->priority = 10; // typical for MX

        $this->assertSame('mail', $record->name);
        $this->assertSame(3600, $record->ttl);
        $this->assertSame('MX', $record->type);
        $this->assertSame(10, $record->priority);
        $this->assertSame('mail.example.com', $record->value);
    }

    public function testSetSrvFields(): void
    {
        $record = new Record('_sip._tcp', 7200, 'IN', 'SRV', 'sip.example.com');
        $record->priority = 5;
        $record->weight   = 10;
        $record->port     = 5060;

        $this->assertSame('_sip._tcp', $record->name);
        $this->assertSame(7200, $record->ttl);
        $this->assertSame('IN', $record->class);
        $this->assertSame('SRV', $record->type);
        $this->assertSame('sip.example.com', $record->value);
        $this->assertSame(5, $record->priority);
        $this->assertSame(10, $record->weight);
        $this->assertSame(5060, $record->port);
    }
}