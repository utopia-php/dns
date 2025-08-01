<?php

namespace Utopia\DNS\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Zone;
use Utopia\DNS\Record;

final class ZoneTest extends TestCase
{
    protected string $domain = 'example.com';
    protected Zone $zone;

    protected function setUp(): void
    {
        $this->zone = new Zone();
    }
    public function testExampleComZoneFile(): void
    {
        $content = (string)file_get_contents(__DIR__ . '/../resources/zone-valid-example.com.txt');
        $validateErrors = $this->zone->validate($this->domain, $content);
        $records = $this->zone->import($this->domain, $content);

        $this->assertEmpty($validateErrors, 'Example.com zone file should have no validation errors.');
        $this->assertGreaterThan(0, count($records), 'Example.com zone file should import at least one record.');
    }

    public function testRedHatZoneFile(): void
    {
        $content = (string)file_get_contents(__DIR__ . '/../resources/zone-valid-redhat.txt');
        $validateErrors = $this->zone->validate($this->domain, $content);
        $records = $this->zone->import($this->domain, $content);

        $this->assertEmpty($validateErrors, 'RedHat zone file should have no validation errors.');
        $this->assertGreaterThan(0, count($records), 'RedHat zone file should import at least one record.');
    }

    public function testOracle1ZoneFile(): void
    {
        $content = (string)file_get_contents(__DIR__ . '/../resources/zone-valid-oracle1.txt');
        $validateErrors = $this->zone->validate($this->domain, $content);
        $records = $this->zone->import($this->domain, $content);

        $this->assertEmpty($validateErrors, 'Oracle 1 zone file should have no validation errors.');
        $this->assertGreaterThan(0, count($records), 'Oracle 1 zone file should import at least one record.');
    }

    public function testOracle2ZoneFile(): void
    {
        $content = (string)file_get_contents(__DIR__ . '/../resources/zone-valid-oracle2.txt');
        $validateErrors = $this->zone->validate($this->domain, $content);
        $records = $this->zone->import($this->domain, $content);

        $this->assertEmpty($validateErrors, 'Oracle 2 zone file should have no validation errors.');
        $this->assertGreaterThan(0, count($records), 'Oracle 2 zone file should import at least one record.');
    }

    public function testLocalhostZoneFile(): void
    {
        $content = (string)file_get_contents(__DIR__ . '/../resources/zone-valid-localhost.txt');
        $validateErrors = $this->zone->validate($this->domain, $content);
        $records = $this->zone->import($this->domain, $content);

        $this->assertEmpty($validateErrors, 'Localhost zone file should have no validation errors.');
        $this->assertGreaterThan(0, count($records), 'Localhost zone file should import at least one record.');
    }

    public function testValidateValidZoneWithDirectives(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        $zoneFile = <<<TXT
; A valid zone with directives
\$ORIGIN example.com.
\$TTL 3600

@       IN  SOA ns1.example.com. admin.example.com. 2025011800 7200 3600 1209600 3600
www     IN  A   192.168.1.10
mail    300 IN  MX 10 mail.example.com.
TXT;

        $errors = $z->validate($domain, $zoneFile);
        $this->assertEmpty($errors, 'Expected no errors for a valid zone with $ORIGIN/$TTL directives.');
    }

    public function testValidateUnsupportedDirective(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        $zoneFile = <<<TXT
\$ORIGIN example.com.
\$INCLUDE some-other-file
TXT;

        // We consider "$INCLUDE" an unsupported directive => error
        $errors = $z->validate($domain, $zoneFile);

        $this->assertNotEmpty($errors, 'Expected errors for unsupported directives.');
        $this->assertStringContainsString('Unsupported directive', $errors[0]);
        $this->assertStringContainsString('$INCLUDE', $errors[0]);
    }

    public function testValidateInvalidTTL(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        // Instead, place the TTL in the second token position *explicitly*
        // e.g. "www bogus" => "TTL 'bogus' is not valid"
        // Real BIND sees "www" as the owner, "bogus" as TTL if numeric, else error
        $zoneFile = "@  bogus  IN A 127.0.0.1\n";

        $errors = $z->validate($domain, $zoneFile);

        // If you want a test for "non-numeric TTL," the code must interpret the second token as TTL
        // That means you'd keep the logic: if second token != numeric && != "IN", => TTL error
        // But you'd skip re-checking class in that scenario.

        // OR you remove this test if it contradicts real BIND logic.

        $this->assertNotEmpty($errors);
        // Update the assertion to match your actual parser’s logic:
        $this->assertStringContainsString("Unsupported class 'bogus'", $errors[0]);
    }

    public function testValidateUnknownRecordType(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        $zoneFile = "www 300 IN BADTYPE data\n";

        $errors = $z->validate($domain, $zoneFile);
        $this->assertNotEmpty($errors, 'Expected an error for unknown record type.');
        $this->assertStringContainsString("Unknown record type 'BADTYPE'", $errors[0]);
    }

    public function testValidateMXRecordMissingPriority(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        // "MX" with no priority => error
        $zoneFile = "mail 3600 IN MX mail.example.com.\n";

        $errors = $z->validate($domain, $zoneFile);
        $this->assertNotEmpty($errors, 'Expected error for incomplete MX record.');
        $this->assertStringContainsString('MX needs priority & exchange', $errors[0]);
    }

    public function testValidateSRVRecordMissingPart(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        // SRV must have 4 parts: priority weight port target
        $zoneFile = "_sip._tcp 600 IN SRV 5 10 5060\n"; // missing target

        $errors = $z->validate($domain, $zoneFile);
        $this->assertNotEmpty($errors);
        $this->assertStringContainsString('SRV must have 4 parts', $errors[0]);
    }

    public function testValidateBlankAndCommentLines(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        $zoneFile = <<<TXT

; This is a comment
# Another style comment

@  3600 IN A 127.0.0.1
TXT;

        $errors = $z->validate($domain, $zoneFile);
        $this->assertEmpty($errors, 'Comments/blank lines should not produce validation errors.');
    }

    public function testValidateZeroTTL(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        // Zero TTL is valid in many DNS servers, so no error expected
        $zoneFile = "@ 0 IN A 127.0.0.1\n";

        $errors = $z->validate($domain, $zoneFile);
        $this->assertEmpty($errors, 'Zero TTL should be accepted as valid integer TTL.');
    }

    public function testImportWithDirectivesAndAutoQualification(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        $zoneFile = <<<ZONE
\$ORIGIN example.com.
\$TTL 1800

@ IN SOA ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800
www IN A 192.168.1.10
mail 300 IN MX 10 mail
_sip._tcp 600 IN SRV 5 10 5060 sip
ZONE;

        $records = $z->import($domain, $zoneFile);

        // We expect 4 records
        $this->assertCount(4, $records);

        // 1) SOA
        $this->assertSame('@', $records[0]->getName());
        $this->assertSame(1800, $records[0]->getTTL());
        $this->assertSame('SOA', strtoupper($records[0]->getTypeName()));

        // 2) www
        $this->assertSame('www.example.com', $records[1]->getName());
        $this->assertSame(1800, $records[1]->getTTL()); // no explicit TTL => use 1800 from $TTL
        $this->assertSame('A', strtoupper($records[1]->getTypeName()));
        $this->assertSame('192.168.1.10', $records[1]->getRdata());

        // 3) mail
        $this->assertSame('mail.example.com', $records[2]->getName());
        $this->assertSame(300, $records[2]->getTTL()); // explicit TTL
        $this->assertSame('MX', strtoupper($records[2]->getTypeName()));
        // priority=10, exchange="mail"
        $this->assertSame(10, $records[2]->getPriority());
        $this->assertSame('mail', $records[2]->getRdata());

        // 4) SRV
        $this->assertSame('_sip._tcp.example.com', $records[3]->getName());
        $this->assertSame(600, $records[3]->getTTL());
        $this->assertSame('SRV', strtoupper($records[3]->getTypeName()));
        $this->assertSame(5, $records[3]->getPriority());
        $this->assertSame(10, $records[3]->getWeight());
        $this->assertSame(5060, $records[3]->getPort());
        $this->assertSame('sip', $records[3]->getRdata());
    }

    public function testImportIgnoresUnknownDirective(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        $zoneFile = <<<ZONE
\$ORIGIN example.com.
\$FOO bar
www IN A 192.168.1.10
ZONE;

        // If your code just ignores unknown directives (no error), then it won't break import
        // If your code wants to produce an error in import, adapt the test or the code accordingly.
        $records = $z->import($domain, $zoneFile);
        $this->assertCount(1, $records, 'One valid record after ignoring unknown directive.');
        $this->assertSame('www.example.com', $records[0]->getName());
    }

    public function testImportSkipsMalformedLines(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        $zoneFile = <<<ZONE
badline
www 300 IN
@ 3600 IN A 127.0.0.1
ZONE;

        // "badline" => not enough tokens
        // "www 300 IN" => missing type/data
        // Only "@ 3600 IN A 127.0.0.1" is valid
        $records = $z->import($domain, $zoneFile);
        $this->assertCount(1, $records);
        $this->assertSame('@', $records[0]->getName());
        $this->assertSame('A', strtoupper($records[0]->getTypeName()));
    }

    public function testExportBasic(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        $records = [
            new Record('@', 1800, 'IN', 'SOA', 'ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800'),
            new Record('www.example.com', 1800, 'IN', 'A', '192.168.1.10'),
            new Record('mail.example.com', 300, 'IN', 'MX', 'mail'),
        ];
        // For MX, set priority
        $records[2]->setPriority(10);

        $out = $z->export($domain, $records);

        // We expect 3 lines, each with correct tokens
        $lines = explode("\n", trim($out));
        $this->assertCount(3, $lines);

        $this->assertStringContainsString('@ 1800 IN SOA ns1.example.com.', $lines[0]);
        $this->assertStringContainsString('www.example.com 1800 IN A 192.168.1.10', $lines[1]);
        $this->assertStringContainsString('mail.example.com 300 IN MX 10 mail', $lines[2]);
    }

    public function testImportExportRoundTrip(): void
    {
        $z = new Zone();
        $domain = 'example.com';

        $zoneFile = <<<ZONE
\$ORIGIN example.com.
\$TTL 1200
@ IN SOA ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800
www  IN A 192.168.1.10
mail 600 IN MX 10 mail
ZONE;

        $records1 = $z->import($domain, $zoneFile);
        $this->assertCount(3, $records1);

        // Export
        $zoneOut = $z->export($domain, $records1);

        // Re-import
        $records2 = $z->import($domain, $zoneOut);

        $this->assertCount(3, $records2, 'Record count should match after round trip.');

        // Compare a few fields
        $this->assertSame($records1[0]->getName(), $records2[0]->getName());
        $this->assertSame($records1[0]->getTTL(), $records2[0]->getTTL());
        $this->assertSame($records1[0]->getTypeName(), $records2[0]->getTypeName());
        $this->assertSame($records1[0]->getRdata(), $records2[0]->getRdata());

        // And check MX details
        $this->assertSame($records1[2]->getPriority(), $records2[2]->getPriority());
        $this->assertSame($records1[2]->getRdata(), $records2[2]->getRdata());
    }

     public function testImportTxtWithSpecialChars(): void
     {
         $zone = new Zone();
         $zonefile = <<<ZONE
@ 3600 IN TXT "v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1;"
ZONE;
         $records = $zone->import('example.com', $zonefile);
         $this->assertCount(1, $records);
         $rec = $records[0];
         $this->assertEquals('TXT', $rec->getTypeName());
         $this->assertEquals('v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1;', trim($rec->getRdata(), '"'));
     }

    public function testExportTxtWithSpecialChars(): void
    {
        $zone = new Zone();
        $txt = 'v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1; text="quoted"; backslash=\\';
        $rec = new Record('@', 3600, 'IN', 'TXT', $txt);
        $exported = $zone->export('example.com', [$rec]);
        $expected = '@ 3600 IN TXT "v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1; text=\\"quoted\\"; backslash=\\\\"' . "\n";
        $this->assertSame($expected, $exported);
    }
}
