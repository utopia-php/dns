<?php

require __DIR__ . '/../../vendor/autoload.php';

use Utopia\DNS\Server;
use Utopia\DNS\Adapter\Swoole;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Resolver\Memory;
use Utopia\DNS\Zone;
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

$zone = new Zone(
    name: 'appwrite.io',
    records: $records,
    soa: new Record(
        name: 'appwrite.io',
        type: Record::TYPE_SOA,
        rdata: 'ns1.appwrite.zone team.appwrite.io 1 7200 1800 1209600 3600',
        ttl: 30
    )
);

$dns = new Server($server, new Memory($zone));
$dns->setDebug(false);

$dns->onWorkerStart(function (Server $server, int $workerId) {
    $span = Span::init();
    $span->set('action', 'dns.worker.start');
    $span->set('worker.id', $workerId);
    $span->finish();
});

$dns->start();
