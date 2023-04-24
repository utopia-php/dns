<?php

namespace Utopia\Tests;

use PHPUnit\Framework\TestCase;

class DNSClientTest extends TestCase
{
    /**
     * @var array<string, mixed> $options
     */
    protected array $options = [
        'nameservers' => array('127.0.0.1')
    ];

    public function testARecords(): void
    {
        $records = (array) \dns_get_record('dev.appwrite.io', DNS_A, $this->options);

        $this->assertCount(1, $records);
        $this->assertEquals('dev.appwrite.io', $records[0]['host']);
        $this->assertEquals('IN', $records[0]['class']);
        $this->assertIsNumeric($records[0]['ttl']);
        $this->assertEquals(10, $records[0]['ttl']);
        $this->assertEquals('A', $records[0]['type']);
        $this->assertEquals('180.12.3.24', $records[0]['ip']);

        $records = (array) \dns_get_record('dev2.appwrite.io', DNS_A, $this->options);

        $this->assertCount(2, $records);
        $this->assertEquals('dev2.appwrite.io', $records[0]['host']);
        $this->assertEquals('IN', $records[0]['class']);
        $this->assertIsNumeric($records[0]['ttl']);
        $this->assertEquals(1800, $records[0]['ttl']);
        $this->assertEquals('A', $records[0]['type']);
        $this->assertEquals('142.6.0.1', $records[0]['ip']);
        $this->assertEquals('dev2.appwrite.io', $records[1]['host']);
        $this->assertEquals('IN', $records[1]['class']);
        $this->assertIsNumeric($records[1]['ttl']);
        $this->assertEquals(1800, $records[1]['ttl']);
        $this->assertEquals('A', $records[1]['type']);
        $this->assertEquals('142.6.0.2', $records[1]['ip']);

        $records = (array) \dns_get_record('dev3.appwrite.io', DNS_A, $this->options);
        $this->assertCount(0, $records);
    }

    public function testAAAARecords(): void
    {
        $records = (array) \dns_get_record('dev.appwrite.io', DNS_AAAA, $this->options);

        $this->assertCount(1, $records);
        $this->assertEquals('dev.appwrite.io', $records[0]['host']);
        $this->assertEquals('IN', $records[0]['class']);
        $this->assertIsNumeric($records[0]['ttl']);
        $this->assertEquals(20, $records[0]['ttl']);
        $this->assertEquals('AAAA', $records[0]['type']);
        $this->assertEquals('2001:db8::ff00:42:8329', $records[0]['ipv6']);

        $records = (array) \dns_get_record('dev2.appwrite.io', DNS_AAAA, $this->options);

        $this->assertCount(2, $records);
        $this->assertEquals('dev2.appwrite.io', $records[0]['host']);
        $this->assertEquals('IN', $records[0]['class']);
        $this->assertIsNumeric($records[0]['ttl']);
        $this->assertEquals(1800, $records[0]['ttl']);
        $this->assertEquals('AAAA', $records[0]['type']);
        $this->assertEquals('2001:db8::ff00:0:1', $records[0]['ipv6']);
        $this->assertEquals('dev2.appwrite.io', $records[1]['host']);
        $this->assertEquals('IN', $records[1]['class']);
        $this->assertIsNumeric($records[1]['ttl']);
        $this->assertEquals(1800, $records[1]['ttl']);
        $this->assertEquals('AAAA', $records[1]['type']);
        $this->assertEquals('2001:db8::ff00:0:2', $records[1]['ipv6']);

        $records = (array) \dns_get_record('dev3.appwrite.io', DNS_AAAA, $this->options);
        $this->assertCount(0, $records);
    }

    public function testCNAMERecords(): void
    {
        $records = (array) \dns_get_record('dev.appwrite.io', DNS_CNAME, $this->options);

        $this->assertCount(1, $records);
        $this->assertEquals('dev.appwrite.io', $records[0]['host']);
        $this->assertEquals('IN', $records[0]['class']);
        $this->assertIsNumeric($records[0]['ttl']);
        $this->assertEquals(30, $records[0]['ttl']);
        $this->assertEquals('CNAME', $records[0]['type']);
        $this->assertEquals('cloud.appwrite.io', $records[0]['target']);

        $records = (array) \dns_get_record('dev2.appwrite.io', DNS_CNAME, $this->options);

        $this->assertCount(2, $records);
        $this->assertEquals('dev2.appwrite.io', $records[0]['host']);
        $this->assertEquals('IN', $records[0]['class']);
        $this->assertIsNumeric($records[0]['ttl']);
        $this->assertEquals(1800, $records[0]['ttl']);
        $this->assertEquals('CNAME', $records[0]['type']);
        $this->assertEquals('eu.cloud.appwrite.io', $records[0]['target']);
        $this->assertEquals('dev2.appwrite.io', $records[1]['host']);
        $this->assertEquals('IN', $records[1]['class']);
        $this->assertIsNumeric($records[1]['ttl']);
        $this->assertEquals(1800, $records[1]['ttl']);
        $this->assertEquals('CNAME', $records[1]['type']);
        $this->assertEquals('us.cloud.appwrite.io', $records[1]['target']);

        $records = (array) \dns_get_record('dev3.appwrite.io', DNS_AAAA, $this->options);
        $this->assertCount(0, $records);
    }

    public function testTXTRecords(): void
    {
        $records = (array) \dns_get_record('dev.appwrite.io', DNS_TXT, $this->options);

        $this->assertCount(1, $records);
        $this->assertEquals('dev.appwrite.io', $records[0]['host']);
        $this->assertEquals('IN', $records[0]['class']);
        $this->assertIsNumeric($records[0]['ttl']);
        $this->assertEquals(40, $records[0]['ttl']);
        $this->assertEquals('TXT', $records[0]['type']);
        $this->assertEquals('awesome-secret-key', $records[0]['entries'][0]);

        $records = (array) \dns_get_record('dev2.appwrite.io', DNS_TXT, $this->options);

        $this->assertCount(2, $records);
        $this->assertEquals('dev2.appwrite.io', $records[0]['host']);
        $this->assertEquals('IN', $records[0]['class']);
        $this->assertIsNumeric($records[0]['ttl']);
        $this->assertEquals(1800, $records[0]['ttl']);
        $this->assertEquals('TXT', $records[0]['type']);
        $this->assertEquals('key with "$\'- symbols', $records[0]['entries'][0]);
        $this->assertEquals('dev2.appwrite.io', $records[1]['host']);
        $this->assertEquals('IN', $records[1]['class']);
        $this->assertIsNumeric($records[1]['ttl']);
        $this->assertEquals(1800, $records[1]['ttl']);
        $this->assertEquals('TXT', $records[1]['type']);
        $this->assertEquals('key with spaces', $records[1]['entries'][0]);

        $records = (array) \dns_get_record('dev3.appwrite.io', DNS_TXT, $this->options);
        $this->assertCount(0, $records);
    }

    public function testCAARecords(): void
    {
        // TODO: Uncomment
        // $records = (array) \dns_get_record('dev.appwrite.io', DNS_CAA, $this->options);

        // $this->assertCount(1, $records);
        // $this->assertEquals('dev.appwrite.io', $records[0]['host']);
        // $this->assertEquals('IN', $records[0]['class']);
        // $this->assertIsNumeric($records[0]['ttl']);
        // $this->assertEquals(50, $records[0]['ttl']);
        // $this->assertEquals('TXT', $records[0]['type']);
        // $this->assertEquals('issue "letsencrypt.org"', $records[0]['value']);

        // $records = (array) \dns_get_record('dev2.appwrite.io', DNS_CAA, $this->options);

        // $this->assertCount(2, $records);
        // $this->assertEquals('dev2.appwrite.io', $records[0]['host']);
        // $this->assertEquals('IN', $records[0]['class']);
        // $this->assertIsNumeric($records[0]['ttl']);
        // $this->assertEquals(1800, $records[0]['ttl']);
        // $this->assertEquals('CAA', $records[0]['type']);
        // $this->assertEquals('issue "letsencrypt.org"', $records[0]['value']);
        // $this->assertEquals('dev2.appwrite.io', $records[1]['host']);
        // $this->assertEquals('IN', $records[1]['class']);
        // $this->assertIsNumeric($records[1]['ttl']);
        // $this->assertEquals(1800, $records[1]['ttl']);
        // $this->assertEquals('CAA', $records[1]['type']);
        // $this->assertEquals('issue "sectigo.com"', $records[1]['value']);

        $records = (array) \dns_get_record('dev3.appwrite.io', DNS_CAA, $this->options);
        $this->assertCount(0, $records);
    }

    public function testNSRecords(): void
    {
        $records = (array) \dns_get_record('dev.appwrite.io', DNS_NS, $this->options);

        $this->assertCount(1, $records);
        $this->assertEquals('dev.appwrite.io', $records[0]['host']);
        $this->assertEquals('IN', $records[0]['class']);
        $this->assertIsNumeric($records[0]['ttl']);
        $this->assertEquals(60, $records[0]['ttl']);
        $this->assertEquals('NS', $records[0]['type']);
        $this->assertEquals('ns.appwrite.io', $records[0]['target']);

        $records = (array) \dns_get_record('dev2.appwrite.io', DNS_NS, $this->options);

        $this->assertCount(2, $records);
        $this->assertEquals('dev2.appwrite.io', $records[0]['host']);
        $this->assertEquals('IN', $records[0]['class']);
        $this->assertIsNumeric($records[0]['ttl']);
        $this->assertEquals(1800, $records[0]['ttl']);
        $this->assertEquals('NS', $records[0]['type']);
        $this->assertEquals('ns1.appwrite.io', $records[0]['target']);
        $this->assertEquals('dev2.appwrite.io', $records[1]['host']);
        $this->assertEquals('IN', $records[1]['class']);
        $this->assertIsNumeric($records[1]['ttl']);
        $this->assertEquals(1800, $records[1]['ttl']);
        $this->assertEquals('NS', $records[1]['type']);
        $this->assertEquals('ns2.appwrite.io', $records[1]['target']);

        $records = (array) \dns_get_record('dev3.appwrite.io', DNS_AAAA, $this->options);
        $this->assertCount(0, $records);
    }

    // TOOD: SRV, MX
}
