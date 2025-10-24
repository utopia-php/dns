<?php

namespace Tests\Utopia\DNS;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Zone;

final class ZoneTest extends TestCase
{
    public function testExampleComZoneFile(): void
    {
        $zone = new Zone();
        $domain = 'example.com';
        $content = (string)file_get_contents(__DIR__ . '/../../resources/zone-valid-example.com.txt');
        $validateErrors = $zone->validate($domain, $content);
        $records = $zone->import($domain, $content);

        $this->assertEmpty($validateErrors, 'Example.com zone file should have no validation errors.');
        $this->assertGreaterThan(0, count($records), 'Example.com zone file should import at least one record.');
    }

    public function testRedHatZoneFile(): void
    {
        $zone = new Zone();
        $domain = 'example.com';
        $content = (string)file_get_contents(__DIR__ . '/../../resources/zone-valid-redhat.txt');
        $validateErrors = $zone->validate($domain, $content);
        $records = $zone->import($domain, $content);

        $this->assertEmpty($validateErrors, 'RedHat zone file should have no validation errors.');
        $this->assertGreaterThan(0, count($records), 'RedHat zone file should import at least one record.');
    }

    public function testOracle1ZoneFile(): void
    {
        $zone = new Zone();
        $domain = 'example.com';
        $content = (string)file_get_contents(__DIR__ . '/../../resources/zone-valid-oracle1.txt');
        $validateErrors = $zone->validate($domain, $content);
        $records = $zone->import($domain, $content);

        $this->assertEmpty($validateErrors, 'Oracle 1 zone file should have no validation errors.');
        $this->assertGreaterThan(0, count($records), 'Oracle 1 zone file should import at least one record.');
    }

    public function testOracle2ZoneFile(): void
    {
        $zone = new Zone();
        $domain = 'example.com';
        $content = (string)file_get_contents(__DIR__ . '/../../resources/zone-valid-oracle2.txt');
        $validateErrors = $zone->validate($domain, $content);
        $records = $zone->import($domain, $content);

        $this->assertEmpty($validateErrors, 'Oracle 2 zone file should have no validation errors.');
        $this->assertGreaterThan(0, count($records), 'Oracle 2 zone file should import at least one record.');
    }

    public function testLocalhostZoneFile(): void
    {
        $zone = new Zone();
        $domain = 'example.com';
        $content = (string)file_get_contents(__DIR__ . '/../../resources/zone-valid-localhost.txt');
        $validateErrors = $zone->validate($domain, $content);
        $records = $zone->import($domain, $content);

        $this->assertEmpty($validateErrors, 'Localhost zone file should have no validation errors.');
        $this->assertGreaterThan(0, count($records), 'Localhost zone file should import at least one record.');
    }

    public function testValidateValidZoneWithDirectives(): void
    {
        $zone = new Zone();
        $domain = 'example.com';

        $file = <<<TXT
; A valid zone with directives
\$ORIGIN example.com.
\$TTL 3600

@       IN  SOA ns1.example.com. admin.example.com. 2025011800 7200 3600 1209600 3600
www     IN  A   192.168.1.10
mail    300 IN  MX 10 mail.example.com.
TXT;

        $errors = $zone->validate($domain, $file);
        $this->assertEmpty($errors, 'Expected no errors for a valid zone with $ORIGIN/$TTL directives.');
    }

    public function testValidateUnsupportedDirective(): void
    {
        $zone = new Zone();
        $domain = 'example.com';

        $file = <<<TXT
\$ORIGIN example.com.
\$INCLUDE some-other-file
TXT;

        $errors = $zone->validate($domain, $file);

        $this->assertNotEmpty($errors, 'Expected errors for unsupported directives.');
        $this->assertStringContainsString('Unsupported directive', $errors[0]);
        $this->assertStringContainsString('$INCLUDE', $errors[0]);
    }

    public function testValidateInvalidTTL(): void
    {
        $zone = new Zone();
        $domain = 'example.com';
        $file = "@  bogus  IN A 127.0.0.1\n";

        $errors = $zone->validate($domain, $file);

        $this->assertNotEmpty($errors);
        $this->assertStringContainsString("Unsupported class 'bogus'", $errors[0]);
    }

    public function testValidateUnknownRecordType(): void
    {
        $zone = new Zone();
        $domain = 'example.com';

        $file = "www 300 IN BADTYPE data\n";

        $errors = $zone->validate($domain, $file);
        $this->assertNotEmpty($errors, 'Expected an error for unknown record type.');
        $this->assertStringContainsString("Unknown record type 'BADTYPE'", $errors[0]);
    }

    public function testValidateMXRecordMissingPriority(): void
    {
        $zone = new Zone();
        $domain = 'example.com';
        $file = "mail 3600 IN MX mail.example.com.\n";

        $errors = $zone->validate($domain, $file);
        $this->assertNotEmpty($errors, 'Expected error for incomplete MX record.');
        $this->assertStringContainsString('MX needs priority & exchange', $errors[0]);
    }

    public function testValidateSRVRecordMissingPart(): void
    {
        $zone = new Zone();
        $domain = 'example.com';
        $file = "_sip._tcp 600 IN SRV 5 10 5060\n";

        $errors = $zone->validate($domain, $file);
        $this->assertNotEmpty($errors);
        $this->assertStringContainsString('SRV must have 4 parts', $errors[0]);
    }

    public function testValidateBlankAndCommentLines(): void
    {
        $zone = new Zone();
        $domain = 'example.com';

        $file = <<<TXT

; This is a comment
# Another style comment

@  3600 IN A 127.0.0.1
TXT;

        $errors = $zone->validate($domain, $file);
        $this->assertEmpty($errors, 'Comments/blank lines should not produce validation errors.');
    }

    public function testValidateZeroTTL(): void
    {
        $zone = new Zone();
        $domain = 'example.com';
        $file = "@ 0 IN A 127.0.0.1\n";

        $errors = $zone->validate($domain, $file);
        $this->assertEmpty($errors, 'Zero TTL should be accepted as valid integer TTL.');
    }

    public function testValidateSOARecordEmptyData(): void
    {
        $zone = new Zone();
        $domain = 'example.com';
        $file = "example.com. 3600 IN SOA";

        $errors = $zone->validate($domain, $file);
        $this->assertNotEmpty($errors, 'Expected validation error for SOA with empty data');
        $this->assertStringContainsString('SOA record has empty data', $errors[0]);
    }

    public function testValidateSOARecordValidData(): void
    {
        $zone = new Zone();
        $domain = 'example.com';
        $file = "@ IN SOA ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800\n";

        $errors = $zone->validate($domain, $file);
        $this->assertEmpty($errors, 'Valid SOA record should not produce errors.');
    }

    public function testImportWithDirectivesAndAutoQualification(): void
    {
        $zone = new Zone();
        $domain = 'example.com';

        $file = <<<ZONE
\$ORIGIN example.com.
\$TTL 1800

@ IN SOA ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800
www IN A 192.168.1.10
mail 300 IN MX 10 mail
_sip._tcp 600 IN SRV 5 10 5060 sip
ZONE;

        $records = $zone->import($domain, $file);

        $this->assertCount(4, $records);

        $this->assertSame('@', $records[0]->name);
        $this->assertSame(1800, $records[0]->ttl);
        $this->assertSame(Record::TYPE_SOA, $records[0]->type);

        $this->assertSame('www.example.com', $records[1]->name);
        $this->assertSame(1800, $records[1]->ttl);
        $this->assertSame(Record::TYPE_A, $records[1]->type);
        $this->assertSame('192.168.1.10', $records[1]->rdata);

        $this->assertSame('mail.example.com', $records[2]->name);
        $this->assertSame(300, $records[2]->ttl);
        $this->assertSame(Record::TYPE_MX, $records[2]->type);
        $this->assertSame(10, $records[2]->priority);
        $this->assertSame('mail', $records[2]->rdata);

        $this->assertSame('_sip._tcp.example.com', $records[3]->name);
        $this->assertSame(600, $records[3]->ttl);
        $this->assertSame(Record::TYPE_SRV, $records[3]->type);
        $this->assertSame(5, $records[3]->priority);
        $this->assertSame(10, $records[3]->weight);
        $this->assertSame(5060, $records[3]->port);
        $this->assertSame('sip', $records[3]->rdata);
    }

    public function testImportIgnoresUnknownDirective(): void
    {
        $zone = new Zone();
        $domain = 'example.com';

        $file = <<<ZONE
\$ORIGIN example.com.
\$FOO bar
www IN A 192.168.1.10
ZONE;

        $records = $zone->import($domain, $file);
        $this->assertCount(1, $records, 'One valid record after ignoring unknown directive.');
        $this->assertSame('www.example.com', $records[0]->name);
    }

    public function testImportSkipsMalformedLines(): void
    {
        $zone = new Zone();
        $domain = 'example.com';

        $file = <<<ZONE
badline
www 300 IN
@ 3600 IN A 127.0.0.1
ZONE;

        $records = $zone->import($domain, $file);
        $this->assertCount(1, $records);
        $this->assertSame('@', $records[0]->name);
        $this->assertSame(Record::TYPE_A, $records[0]->type);
    }

    public function testExportBasic(): void
    {
        $zone = new Zone();
        $domain = 'example.com';

        $records = [
            new Record('@', Record::TYPE_SOA, Record::CLASS_IN, 1800, 'ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800'),
            new Record('www.example.com', Record::TYPE_A, Record::CLASS_IN, 1800, '192.168.1.10'),
            new Record('mail.example.com', Record::TYPE_MX, Record::CLASS_IN, 300, 'mail', priority: 10),
        ];

        $out = $zone->export($domain, $records);

        $lines = explode("\n", trim($out));
        $this->assertCount(3, $lines);

        $this->assertStringContainsString('@ 1800 IN SOA ns1.example.com.', $lines[0]);
        $this->assertStringContainsString('www.example.com 1800 IN A 192.168.1.10', $lines[1]);
        $this->assertStringContainsString('mail.example.com 300 IN MX 10 mail', $lines[2]);
    }

    public function testImportExportRoundTrip(): void
    {
        $zone = new Zone();
        $domain = 'example.com';

        $file = <<<ZONE
\$ORIGIN example.com.
\$TTL 1200
@ IN SOA ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800
www  IN A 192.168.1.10
mail 600 IN MX 10 mail
ZONE;

        $records1 = $zone->import($domain, $file);
        $this->assertCount(3, $records1);

        $zoneOut = $zone->export($domain, $records1);
        $records2 = $zone->import($domain, $zoneOut);

        $this->assertCount(3, $records2, 'Record count should match after round trip.');

        $this->assertSame($records1[0]->name, $records2[0]->name);
        $this->assertSame($records1[0]->ttl, $records2[0]->ttl);
        $this->assertSame($records1[0]->type, $records2[0]->type);
        $this->assertSame($records1[0]->rdata, $records2[0]->rdata);

        $this->assertSame($records1[2]->priority, $records2[2]->priority);
        $this->assertSame($records1[2]->rdata, $records2[2]->rdata);
    }

    public function testImportTxtWithSpecialChars(): void
    {
        $zone = new Zone();
        $file = <<<ZONE
@ 3600 IN TXT "v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1;"
ZONE;
        $records = $zone->import('example.com', $file);
        $this->assertCount(1, $records);
        $this->assertSame(Record::TYPE_TXT, $records[0]->type);
        $this->assertSame('v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1;', trim($records[0]->rdata, '"'));
    }

    public function testExportTxtWithSpecialChars(): void
    {
        $zone = new Zone();
        $txt = 'v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1; text="quoted"; backslash=\\';
        $record = new Record('@', Record::TYPE_TXT, Record::CLASS_IN, 3600, $txt);
        $exported = $zone->export('example.com', [$record]);
        $expected = '@ 3600 IN TXT "v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1; text=\\"quoted\\"; backslash=\\\\"' . "\n";
        $this->assertSame($expected, $exported);
    }
}
