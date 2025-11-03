<?php

namespace Tests\Utopia\DNS\Zone;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Zone;
use Utopia\DNS\Zone\File;

final class FileTest extends TestCase
{
    private const string DEFAULT_SOA = '@ IN SOA ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800';

    public function testExampleComZoneFile(): void
    {
        $content = (string) file_get_contents(__DIR__ . '/../../../resources/zone-valid-example.com.txt');

        $zone = File::import('example.com', $content);

        $this->assertSame('example.com', $zone->name);
        $this->assertNotEmpty($zone->records);
    }

    public function testRedHatZoneFile(): void
    {
        $content = (string) file_get_contents(__DIR__ . '/../../../resources/zone-valid-redhat.txt');

        $zone = File::import('example.com', $content);

        $this->assertSame('example.com', $zone->name);
        $this->assertNotEmpty($zone->records);
    }

    public function testOracle1ZoneFile(): void
    {
        $content = (string) file_get_contents(__DIR__ . '/../../../resources/zone-valid-oracle1.txt');

        $zone = File::import('example.com', $content);

        $this->assertSame('example.com', $zone->name);
        $this->assertNotEmpty($zone->records);
    }

    public function testOracle2ZoneFile(): void
    {
        $content = (string) file_get_contents(__DIR__ . '/../../../resources/zone-valid-oracle2.txt');

        $zone = File::import('example.com', $content);

        $this->assertSame('example.com', $zone->name);
        $this->assertNotEmpty($zone->records);
    }

    public function testLocalhostZoneFile(): void
    {
        $content = (string) file_get_contents(__DIR__ . '/../../../resources/zone-valid-localhost.txt');

        $zone = File::import('localhost', $content);

        $this->assertSame('localhost', $zone->name);
        $this->assertNotEmpty($zone->records);
    }

    public function testImportValidZoneWithDirectives(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
\$TTL 1800
{$soa}

www IN A 192.168.1.10
mail 300 IN MX 10 mail
_sip._tcp 600 IN SRV 5 10 5060 sip
ZONE;

        $zone = File::import('example.com', $contents);

        $this->assertSame(1800, $zone->soa->ttl);
        $this->assertCount(3, $zone->records);

        $www = $zone->records[0];
        $this->assertSame('www.example.com', $www->name);
        $this->assertSame(1800, $www->ttl);
        $this->assertSame(Record::TYPE_A, $www->type);
        $this->assertSame('192.168.1.10', $www->rdata);

        $mx = $this->findRecord($zone->records, Record::TYPE_MX);
        $this->assertNotNull($mx);
        $this->assertSame(300, $mx->ttl);
        $this->assertSame('mail.example.com', $mx->rdata);
        $this->assertSame(10, $mx->priority);

        $srv = $this->findRecord($zone->records, Record::TYPE_SRV);
        $this->assertNotNull($srv);
        $this->assertSame('_sip._tcp.example.com', $srv->name);
        $this->assertSame(5, $srv->priority);
        $this->assertSame(10, $srv->weight);
        $this->assertSame(5060, $srv->port);
        $this->assertSame('sip.example.com', $srv->rdata);
    }

    public function testImportFailsWithUnsupportedDirective(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('$INCLUDE directive is not supported');

        File::import('example.com', <<<ZONE
\$ORIGIN example.com.
\$INCLUDE other.zone
ZONE);
    }

    public function testImportFailsWithUnknownRecordType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Unknown record type 'BADTYPE'");

        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
www 300 IN BADTYPE data
ZONE;

        File::import('example.com', $contents);
    }

    public function testImportFailsWhenMxPriorityMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('MX requires numeric priority and exchange');

        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
mail 3600 IN MX mail.example.com.
ZONE;

        File::import('example.com', $contents);
    }

    public function testImportFailsWhenSrvFieldsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('SRV requires priority, weight, port, target');

        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
_sip._tcp 600 IN SRV 5 10 5060
ZONE;

        File::import('example.com', $contents);
    }

    public function testImportHandlesBlankLinesAndComments(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}

; comment line

@ 3600 IN A 127.0.0.1
ZONE;

        $zone = File::import('example.com', $contents);

        $this->assertCount(1, $zone->records);
        $this->assertSame('example.com', $zone->records[0]->name);
    }

    public function testImportAllowsZeroTtl(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
@ 0 IN A 127.0.0.1
ZONE;

        $zone = File::import('example.com', $contents);

        $this->assertSame(0, $zone->records[0]->ttl);
    }

    public function testImportFailsWhenSoaDataMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('SOA requires MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM');

        File::import('example.com', '@ IN SOA ns1.example.com. admin.example.com.');
    }

    public function testImportWithRelativeNamesExpandsToZone(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
www     IN  A   192.0.2.10
mail    IN  MX  10 mail
alias   IN  CNAME   www
ZONE;

        $zone = File::import('example.com', $contents);

        $this->assertSame('example.com', $zone->soa->name);

        $mx = $this->findRecord($zone->records, Record::TYPE_MX);
        $this->assertNotNull($mx);
        $this->assertSame('mail.example.com', $mx->rdata);

        $cname = $this->findRecord($zone->records, Record::TYPE_CNAME);
        $this->assertNotNull($cname);
        $this->assertSame('www.example.com', $cname->rdata);
    }

    public function testImportHandlesClassBeforeTtl(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
@ IN 3600 A 192.0.2.10
ZONE;

        $zone = File::import('example.com', $contents);

        $record = $zone->records[0];
        $this->assertSame(Record::CLASS_IN, $record->class);
        $this->assertSame(3600, $record->ttl);
    }

    public function testImportDefaultsClassToIn(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
@ 600 A 192.0.2.11
ZONE;

        $zone = File::import('example.com', $contents);

        $record = $zone->records[0];
        $this->assertSame(Record::CLASS_IN, $record->class);
    }

    public function testImportCollapsesParenthesizedTxtRecords(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
multiline 600 IN TXT (
    "foo"
    "bar"
)
ZONE;

        $zone = File::import('example.com', $contents);
        $txt = $this->findRecord($zone->records, Record::TYPE_TXT);
        $this->assertNotNull($txt);
        $this->assertSame('foobar', $txt->rdata);
    }

    public function testImportDecodesDecimalEscapesInTxt(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
escaped 600 IN TXT "foo\\010bar"
ZONE;

        $zone = File::import('example.com', $contents);
        $txt = $this->findRecord($zone->records, Record::TYPE_TXT);
        $this->assertNotNull($txt);
        $this->assertSame("foo" . chr(10) . "bar", $txt->rdata);
    }

    public function testImportIgnoresUnknownDirective(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
\$FOO bar
www IN A 192.168.1.10
ZONE;

        $zone = File::import('example.com', $contents);

        $this->assertCount(1, $zone->records);
        $this->assertSame('www.example.com', $zone->records[0]->name);
    }

    public function testImportTxtWithSpecialChars(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
@ 3600 IN TXT "v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1;"
ZONE;

        $zone = File::import('example.com', $contents);
        $record = $this->findRecord($zone->records, Record::TYPE_TXT);
        $this->assertNotNull($record);
        $this->assertSame('v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1;', $record->rdata);
    }

    public function testExportTxtWithSpecialChars(): void
    {
        $zone = new Zone(
            'example.com',
            [
                new Record('example.com', Record::TYPE_TXT, Record::CLASS_IN, 3600, 'v=DMARC1; text="quoted"; backslash=\\'),
            ],
            new Record('example.com', Record::TYPE_SOA, Record::CLASS_IN, 3600, 'ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800'),
        );

        $expected = "\$ORIGIN example.com.\n\$TTL 3600\n\n@\t3600\tIN\tSOA\tns1 admin (\n\t\t\t\t2025011801\t; serial\n\t\t\t\t7200\t; refresh\n\t\t\t\t3600\t; retry\n\t\t\t\t1209600\t; expire\n\t\t\t\t1800 )\t; minimum\n\n@\t3600\tIN\tTXT\t\"v=DMARC1; text=\\\"quoted\\\"; backslash=\\\\\"\n";

        $exported = File::export($zone, includeComments: false);
        $this->assertSame($expected, $exported);

        $roundTrip = File::import('example.com', $exported);
        $roundTripTxt = $this->findRecord($roundTrip->records, Record::TYPE_TXT);

        $this->assertNotNull($roundTripTxt);
        $this->assertSame($zone->records[0]->rdata, $roundTripTxt->rdata);
    }

    public function testImportExportRoundTrip(): void
    {
        $contents = <<<ZONE
\$ORIGIN example.com.
\$TTL 1200
@ IN SOA ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800
www IN A 192.168.1.10
mail 600 IN MX 10 mail
ZONE;

        $zone = File::import('example.com', $contents);
        $this->assertCount(2, $zone->records);

        $exported = File::export($zone, includeComments: false);
        $roundTrip = File::import('example.com', $exported);

        $this->assertSame($zone->name, $roundTrip->name);
        $this->assertSame($zone->soa->rdata, $roundTrip->soa->rdata);
        $this->assertCount(count($zone->records), $roundTrip->records);
        $this->assertSame($zone->records[1]->rdata, $roundTrip->records[1]->rdata);
    }

    public function testExportBasicZone(): void
    {
        $zone = new Zone(
            'example.com',
            [
                new Record('example.com', Record::TYPE_NS, Record::CLASS_IN, 3600, 'ns1.example.com'),
                new Record('www.example.com', Record::TYPE_A, Record::CLASS_IN, 1800, '192.168.1.10'),
                new Record('mail.example.com', Record::TYPE_MX, Record::CLASS_IN, 300, 'mail.example.com', priority: 10),
            ],
            new Record('example.com', Record::TYPE_SOA, Record::CLASS_IN, 1800, 'ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800'),
        );

        $expected = "\$ORIGIN example.com.\n\$TTL 1800\n\n@\t1800\tIN\tSOA\tns1 admin (\n\t\t\t\t2025011801\t; serial\n\t\t\t\t7200\t; refresh\n\t\t\t\t3600\t; retry\n\t\t\t\t1209600\t; expire\n\t\t\t\t1800 )\t; minimum\n\n@\t3600\tIN\tNS\tns1\n\nwww\t1800\tIN\tA\t192.168.1.10\n\nmail\t300\tIN\tMX\t10 mail\n";

        $output = File::export($zone, includeComments: false);
        $this->assertSame($expected, $output);

        $roundTrip = File::import('example.com', $output);
        $this->assertCount(3, $roundTrip->records);
        $this->assertSame('mail.example.com', $roundTrip->records[2]->name);
    }

    public function testImportSupportsPtrRecords(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
1 3600 IN PTR host.example.com.
ZONE;

        $zone = File::import('example.com', $contents);
        $ptr = $this->findRecord($zone->records, Record::TYPE_PTR);
        $this->assertNotNull($ptr);
        $this->assertSame('1.example.com', $ptr->name);
        $this->assertSame('host.example.com', $ptr->rdata);
    }

    public function testImportSupportsMultilineSoa(): void
    {
        $contents = <<<'ZONE'
$ORIGIN example.com.
@ 3600 IN SOA (
    ns1.example.com.
    admin.example.com.
    2025011801
    7200
    3600
    1209600
    1800
)
www 1800 IN A 192.0.2.10
ZONE;

        $zone = File::import('example.com', $contents);

        $this->assertSame('ns1.example.com admin.example.com 2025011801 7200 3600 1209600 1800', $zone->soa->rdata);
        $this->assertSame('www.example.com', $zone->records[0]->name);
    }

    public function testImportHandlesMultipleOrigins(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
www IN A 192.0.2.10
\$ORIGIN sub.example.com.
@ 600 IN AAAA 2001:db8::1
\$ORIGIN example.com.
api IN CNAME www
ZONE;

        $zone = File::import('example.com', $contents);

        $this->assertSame('www.example.com', $zone->records[0]->name);
        $this->assertSame('sub.example.com', $zone->records[1]->name);
        $this->assertSame('api.example.com', $zone->records[2]->name);
        $this->assertSame('www.example.com', $zone->records[2]->rdata);
    }

    public function testImportAllowsOwnerOmissionWithPreviousOwner(): void
    {
        $soa = self::DEFAULT_SOA;
        $contents = <<<ZONE
\$ORIGIN example.com.
{$soa}
www IN A 192.0.2.10
    IN AAAA 2001:db8::1
ZONE;

        $zone = File::import('example.com', $contents);

        $this->assertSame('www.example.com', $zone->records[0]->name);
        $this->assertSame('www.example.com', $zone->records[1]->name);
        $this->assertSame(Record::TYPE_AAAA, $zone->records[1]->type);
    }

    public function testImportTxtWithEscapedSemicolon(): void
    {
        $contents = sprintf(
            <<<'ZONE'
$ORIGIN example.com.
%s
@ 3600 IN TXT "foo\;bar"
ZONE,
            self::DEFAULT_SOA
        );

        $zone = File::import('example.com', $contents);
        $record = $this->findRecord($zone->records, Record::TYPE_TXT);
        $this->assertNotNull($record);
        $this->assertSame('foo;bar', $record->rdata);
    }

    public function testImportTxtWithSemicolonInQuotes(): void
    {
        $contents = sprintf(
            <<<'ZONE'
$ORIGIN example.com.
%s
@ 3600 IN TXT "not a comment; still text"
ZONE,
            self::DEFAULT_SOA
        );

        $zone = File::import('example.com', $contents);
        $record = $this->findRecord($zone->records, Record::TYPE_TXT);
        $this->assertNotNull($record);
        $this->assertSame('not a comment; still text', $record->rdata);
    }

    public function testImportExportRoundTripForAaaa(): void
    {
        $contents = sprintf(
            <<<'ZONE'
$ORIGIN example.com.
%s
www 600 IN AAAA 2001:db8::1
ZONE,
            self::DEFAULT_SOA
        );

        $zone = File::import('example.com', $contents);
        $this->assertSame(Record::TYPE_AAAA, $zone->records[0]->type);

        $exported = File::export($zone, includeComments: false);
        $roundTrip = File::import('example.com', $exported);

        $this->assertSame($zone->records[0]->rdata, $roundTrip->records[0]->rdata);
    }

    public function testImportExportRoundTripForCaa(): void
    {
        $contents = sprintf(
            <<<'ZONE'
$ORIGIN example.com.
%s
@ 3600 IN CAA 0 issue "letsencrypt.org"
ZONE,
            self::DEFAULT_SOA
        );

        $zone = File::import('example.com', $contents);
        $record = $this->findRecord($zone->records, Record::TYPE_CAA);
        $this->assertNotNull($record);
        $this->assertSame('0 issue "letsencrypt.org"', $record->rdata);

        $exported = File::export($zone, includeComments: false);
        $roundTrip = File::import('example.com', $exported);
        $roundTripCaa = $this->findRecord($roundTrip->records, Record::TYPE_CAA);

        $this->assertNotNull($roundTripCaa);
        $this->assertSame($record->rdata, $roundTripCaa->rdata);
    }

    public function testImportCaaMissingQuotedValueFails(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/CAA value must be quoted/');

        $contents = sprintf(
            <<<'ZONE'
$ORIGIN example.com.
%s
@ 3600 IN CAA 0 issue letsencrypt.org
ZONE,
            self::DEFAULT_SOA
        );

        File::import('example.com', $contents);
    }

    public function testImportPtrWithReverseOrigin(): void
    {
        $contents = <<<'ZONE'
$ORIGIN 2.0.192.in-addr.arpa.
@ 3600 IN SOA ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800
1 3600 IN PTR host.example.com.
ZONE;

        $zone = File::import('2.0.192.in-addr.arpa.', $contents);
        $ptr = $this->findRecord($zone->records, Record::TYPE_PTR);
        $this->assertNotNull($ptr);
        $this->assertSame('1.2.0.192.in-addr.arpa', $ptr->name);
    }

    public function testImportFailsWithDuplicateSoa(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Multiple SOA records found');

        $contents = <<<'ZONE'
$ORIGIN example.com.
@ IN SOA ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800
@ IN SOA ns2.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800
ZONE;

        File::import('example.com', $contents);
    }

    public function testImportRejectsTtlWithSuffix(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Unknown record type '1H'");

        $contents = sprintf(
            <<<'ZONE'
$ORIGIN example.com.
%s
www 1h IN A 192.0.2.10
ZONE,
            self::DEFAULT_SOA
        );

        File::import('example.com', $contents);
    }

    public function testImportSupportsAlternativeClasses(): void
    {
        $contents = sprintf(
            <<<'ZONE'
$ORIGIN example.com.
%s
www CS A 192.0.2.10
ZONE,
            self::DEFAULT_SOA
        );

        $zone = File::import('example.com', $contents);
        $record = $this->findRecord($zone->records, Record::TYPE_A);
        $this->assertNotNull($record);
        $this->assertSame(Record::CLASS_CS, $record->class);
    }

    public function testImportTxtWithEmbeddedQuoteAndBackslash(): void
    {
        $contents = sprintf(
            <<<'ZONE'
$ORIGIN example.com.
%s
@ 3600 IN TXT "a \"quote\" and a \\ backslash"
ZONE,
            self::DEFAULT_SOA
        );

        $zone = File::import('example.com', $contents);
        $record = $this->findRecord($zone->records, Record::TYPE_TXT);
        $this->assertNotNull($record);
        $this->assertSame('a "quote" and a \\ backslash', $record->rdata);
    }

    public function testImportTxtThreeDigitEscapeConsumesOnlyThreeDigits(): void
    {
        $contents = sprintf(
            <<<'ZONE'
$ORIGIN example.com.
%s
@ 3600 IN TXT "foo\0100bar"
ZONE,
            self::DEFAULT_SOA
        );

        $zone = File::import('example.com', $contents);
        $record = $this->findRecord($zone->records, Record::TYPE_TXT);
        $this->assertNotNull($record);
        $this->assertSame("foo" . chr(10) . "0bar", $record->rdata);
    }

    public function testImportFailsWhenSoaHasTooFewFields(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('SOA requires MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM');

        File::import('example.com', '@ IN SOA ns1.example.com. admin.example.com. 2025011801 7200 3600');
    }

    public function testImportFailsWithoutSoa(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('No SOA record found in zone file');

        File::import('example.com', "www IN A 192.168.1.10\n");
    }

    public function testImportFailsWhenOwnerOmittedWithoutContext(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Owner omitted but no previous owner available');

        File::import('example.com', <<<ZONE
\$ORIGIN example.com.
    IN A 127.0.0.1
@ IN SOA ns1.example.com. admin.example.com. 2025011801 7200 3600 1209600 1800
ZONE);
    }

    /**
     * @param list<Record> $records
     */
    private function findRecord(array $records, int $type): ?Record
    {
        foreach ($records as $record) {
            if ($record->type === $type) {
                return $record;
            }
        }

        return null;
    }
}
