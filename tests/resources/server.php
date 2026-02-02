<?php

require __DIR__ . '/../../vendor/autoload.php';

use Utopia\DNS\Server;
use Utopia\DNS\Adapter\Swoole;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Resolver;
use Utopia\DNS\Zone;
use Utopia\DNS\Zone\File;
use Utopia\DNS\Zone\Resolver as ZoneResolver;
use Utopia\Span\Span;
use Utopia\Span\Storage;
use Utopia\Span\Exporter;

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') !== __FILE__) {
    return;
}

Span::setStorage(new Storage\Coroutine());
Span::addExporter(new Exporter\Stdout());

$port = (int) (getenv('PORT') ?: 5300);
$server = new Swoole('0.0.0.0', $port);

$records = [
    // Single A
    new Record(name: 'dev.appwrite.io', type: Record::TYPE_A, rdata: '180.12.3.24', ttl: 10),
    // Mulple AAAA
    new Record(name: 'dev2.appwrite.io', type: Record::TYPE_A, rdata: '142.6.0.1', ttl: 1800),
    new Record(name: 'dev2.appwrite.io', type: Record::TYPE_A, rdata: '142.6.0.2', ttl: 1800),
    // Single AAAA
    new Record(name: 'dev.appwrite.io', type: Record::TYPE_AAAA, rdata: '2001:0db8:0000:0000:0000:ff00:0042:8329', ttl: 20),
    // Multiple AAAA
    new Record(name: 'dev2.appwrite.io', type: Record::TYPE_AAAA, rdata: '2001:0db8:0000:0000:0000:ff00:0000:0001', ttl: 20),
    new Record(name: 'dev2.appwrite.io', type: Record::TYPE_AAAA, rdata: '2001:0db8:0000:0000:0000:ff00:0000:0002', ttl: 20),
    // Single CNAME
    new Record(name: 'alias.appwrite.io', type: Record::TYPE_CNAME, rdata: 'cloud.appwrite.io', ttl: 30),
    // Secret TXT
    new Record(name: 'dev.appwrite.io', type: Record::TYPE_TXT, rdata: 'awesome-secret-key', ttl: 30),
    // Mail MX
    new Record(name: 'dev.appwrite.io', type: Record::TYPE_MX, rdata: '10 mail.appwrite.io', ttl: 30),
    // Single CAA
    new Record(name: 'dev.appwrite.io', type: Record::TYPE_CAA, rdata: '0 issue "letsencrypt.org"', ttl: 30),
    // Subdomain NS delegation
    new Record(name: 'delegated.appwrite.io', type: Record::TYPE_NS, rdata: 'ns1.test.io', ttl: 30),
    new Record(name: 'delegated.appwrite.io', type: Record::TYPE_NS, rdata: 'ns2.test.io', ttl: 30),
];

$appwriteZone = new Zone(
    name: 'appwrite.io',
    records: $records,
    soa: new Record(
        name: 'appwrite.io',
        type: Record::TYPE_SOA,
        rdata: 'ns1.appwrite.zone team.appwrite.io 1 7200 1800 1209600 3600',
        ttl: 30
    )
);

// Load the localhost zone from zone file (contains large.localhost TXT records for TCP truncation tests)
$localhostZoneContent = (string) file_get_contents(__DIR__ . '/zone-valid-localhost.txt');
$localhostZone = File::import($localhostZoneContent);

/**
 * Simple multi-zone resolver for testing purposes
 */
$multiZoneResolver = new class([$appwriteZone, $localhostZone]) implements Resolver {
    /** @param list<Zone> $zones */
    public function __construct(private readonly array $zones)
    {
    }

    public function resolve(Message $query): Message
    {
        $question = $query->questions[0] ?? null;
        if ($question === null) {
            return Message::response(
                header: $query->header,
                responseCode: Message::RCODE_FORMERR,
                authoritative: true,
            );
        }

        // Find the matching zone for this query
        $queryName = strtolower($question->name);
        foreach ($this->zones as $zone) {
            $zoneName = $zone->name;
            if ($queryName === $zoneName || str_ends_with($queryName, '.' . $zoneName)) {
                return ZoneResolver::lookup($query, $zone);
            }
        }

        // No matching zone found - return NXDOMAIN with first zone's SOA
        return Message::response(
            header: $query->header,
            responseCode: Message::RCODE_NXDOMAIN,
            questions: $query->questions,
            authority: [$this->zones[0]->soa],
            authoritative: true,
        );
    }

    public function getName(): string
    {
        return 'multi-zone-memory';
    }
};

$dns = new Server($server, $multiZoneResolver);
$dns->setDebug(false);

$dns->onWorkerStart(function (Server $server, int $workerId) {
    $span = Span::init('dns.worker.start');
    $span->set('worker.id', $workerId);
    $span->finish();
});

$dns->start();
