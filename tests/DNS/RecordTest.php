<?php

namespace Utopia\DNS\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Record;

final class RecordTest extends TestCase
{
    /**
     * Test that a newly created Record returns default values.
     */
    public function testConstructorDefaults(): void
    {
        $record = new Record();

        // Defaults
        $this->assertSame('', $record->getName());
        $this->assertSame(0, $record->getType());
        $this->assertSame('', $record->getClass());
        $this->assertSame(0, $record->getTTL());
        $this->assertSame('', $record->getRdata());

        // Optional fields should be null by default.
        $this->assertNull($record->getPriority());
        $this->assertNull($record->getWeight());
        $this->assertNull($record->getPort());
    }

    /**
     * Test the setName() and getName() methods.
     */
    public function testSetAndGetName(): void
    {
        $record = new Record();
        $record->setName('www.example.com');
        $this->assertSame('www.example.com', $record->getName());
    }

    /**
     * Test the setTTL() and getTTL() methods.
     */
    public function testSetAndGetTTL(): void
    {
        $record = new Record();
        $record->setTTL(3600);
        $this->assertSame(3600, $record->getTTL());
    }

    /**
     * Test the setClass() and getClass() methods.
     */
    public function testSetAndGetClass(): void
    {
        $record = new Record();
        $record->setClass('IN');
        $this->assertSame('IN', $record->getClass());
    }

    /**
     * Test the setType(), getType(), and getTypeName() methods for an A record.
     */
    public function testSetAndGetTypeForA(): void
    {
        $record = new Record();
        // Set the record type using its numeric value (1 for A)
        $record->setType(1);
        $this->assertSame(1, $record->getType());
        $this->assertSame('A', $record->getTypeName());
    }

    /**
     * Test the setRdata() and getRdata() methods.
     */
    public function testSetAndGetRdata(): void
    {
        $record = new Record();
        $record->setRdata('127.0.0.1');
        $this->assertSame('127.0.0.1', $record->getRdata());
    }

    /**
     * Test the setter and getter for the optional field "priority".
     */
    public function testSetAndGetPriority(): void
    {
        $record = new Record();
        $this->assertNull($record->getPriority());
        $record->setPriority(10);
        $this->assertSame(10, $record->getPriority());
    }

    /**
     * Test the setter and getter for the optional field "weight".
     */
    public function testSetAndGetWeight(): void
    {
        $record = new Record();
        $this->assertNull($record->getWeight());
        $record->setWeight(20);
        $this->assertSame(20, $record->getWeight());
    }

    /**
     * Test the setter and getter for the optional field "port".
     */
    public function testSetAndGetPort(): void
    {
        $record = new Record();
        $this->assertNull($record->getPort());
        $record->setPort(5060);
        $this->assertSame(5060, $record->getPort());
    }

    /**
     * Test the __toString() method produces the expected output.
     */
    public function testToString(): void
    {
        $record = new Record();
        $record->setName('www.example.com')
               ->setTTL(300)
               ->setClass('IN')
               ->setType(1)
               ->setRdata('127.0.0.1');

        $expected = sprintf(
            "Name: %s, Type: %s, TTL: %d, Data: %s",
            'www.example.com',
            'A',
            300,
            '127.0.0.1'
        );
        $this->assertSame($expected, (string)$record);
    }

    /**
     * Test a record configured for MX.
     */
    public function testMXRecord(): void
    {
        $record = new Record();
        $record->setName('mail.example.com')
               ->setTTL(3600)
               ->setClass('IN')
               ->setType(15) // MX is typically represented by the numeric code 15.
               ->setRdata('mail.example.com')
               ->setPriority(5);

        $this->assertSame('mail.example.com', $record->getName());
        $this->assertSame(3600, $record->getTTL());
        $this->assertSame('MX', $record->getTypeName());
        $this->assertSame('mail.example.com', $record->getRdata());
        $this->assertSame(5, $record->getPriority());
    }

    /**
     * Test a record configured for SRV.
     */
    public function testSRVRecord(): void
    {
        $record = new Record();
        $record->setName('_sip._tcp.example.com')
               ->setTTL(7200)
               ->setClass('IN')
               ->setType(33) // SRV numeric code is 33.
               ->setRdata('sip.example.com')
               ->setPriority(10)
               ->setWeight(20)
               ->setPort(5060);

        $this->assertSame('_sip._tcp.example.com', $record->getName());
        $this->assertSame(7200, $record->getTTL());
        $this->assertSame('IN', $record->getClass());
        $this->assertSame('SRV', $record->getTypeName());
        $this->assertSame('sip.example.com', $record->getRdata());
        $this->assertSame(10, $record->getPriority());
        $this->assertSame(20, $record->getWeight());
        $this->assertSame(5060, $record->getPort());
    }
}
