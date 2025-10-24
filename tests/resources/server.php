<?php

require __DIR__ . '/../../vendor/autoload.php';

use Utopia\DNS\Server;
use Utopia\DNS\Adapter\Swoole;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Resolver\Memory;

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') !== __FILE__) {
    return;
}

$server = new Swoole('0.0.0.0', 54);
$resolver = new Memory();

$resolver->addRecord(new Record(
    name: 'dev.appwrite.io',
    type: Record::TYPE_A,
    rdata: '180.12.3.24',
    ttl: 10
));

$resolver->addRecord(new Record(
    name: 'dev2.appwrite.io',
    type: Record::TYPE_A,
    rdata: '142.6.0.1',
    ttl: 1800
));

$resolver->addRecord(new Record(
    name: 'dev2.appwrite.io',
    type: Record::TYPE_A,
    rdata: '142.6.0.2',
    ttl: 1800
));

$resolver->addRecord(new Record(
    name: 'dev.appwrite.io',
    type: Record::TYPE_AAAA,
    rdata: '2001:0db8:0000:0000:0000:ff00:0042:8329',
    ttl: 20
));

$resolver->addRecord(new Record(
    name: 'dev2.appwrite.io',
    type: Record::TYPE_AAAA,
    rdata: '2001:0db8:0000:0000:0000:ff00:0000:0001'
));

$resolver->addRecord(new Record(
    name: 'dev2.appwrite.io',
    type: Record::TYPE_AAAA,
    rdata: '2001:0db8:0000:0000:0000:ff00:0000:0002'
));

$resolver->addRecord(new Record(
    name: 'alias.appwrite.io',
    type: Record::TYPE_CNAME,
    ttl: 30,
    rdata: 'cloud.appwrite.io'
));

$resolver->addRecord(new Record(
    name: 'alias-eu.appwrite.io',
    type: Record::TYPE_CNAME,
    rdata: 'eu.cloud.appwrite.io'
));

$resolver->addRecord(new Record(
    name: 'alias-us.appwrite.io',
    type: Record::TYPE_CNAME,
    rdata: 'us.cloud.appwrite.io'
));

$resolver->addRecord(new Record(
    name: 'dev.appwrite.io',
    type: Record::TYPE_TXT,
    ttl: 40,
    rdata: 'awesome-secret-key'
));

$resolver->addRecord(new Record(
    name: 'dev2.appwrite.io',
    type: Record::TYPE_TXT,
    rdata: 'key with "$\'- symbols'
));

$resolver->addRecord(new Record(
    name: 'dev2.appwrite.io',
    type: Record::TYPE_TXT,
    rdata: 'key with spaces'
));

$resolver->addRecord(new Record(
    name: 'dev2.appwrite.io',
    type: Record::TYPE_TXT,
    rdata: 'v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1;'
));

$resolver->addRecord(new Record(
    name: 'dev.appwrite.io',
    type: Record::TYPE_CAA,
    ttl: 50,
    rdata: 'issue "letsencrypt.org"'
));

$resolver->addRecord(new Record(
    name: 'dev2.appwrite.io',
    type: Record::TYPE_CAA,
    rdata: 'issue "letsencrypt.org"'
));

$resolver->addRecord(new Record(
    name: 'dev2.appwrite.io',
    type: Record::TYPE_CAA,
    rdata: 'issue "sectigo.com"'
));

$resolver->addRecord(new Record(
    name: 'dev3.appwrite.io',
    type: Record::TYPE_CAA,
    rdata: '255 issuewild "certainly.com;validationmethods=tls-alpn-01;retrytimeout=3600"'
));

$resolver->addRecord(new Record(
    name: 'dev.appwrite.io',
    type: Record::TYPE_NS,
    ttl: 60,
    rdata: 'ns.appwrite.io'
));

$resolver->addRecord(new Record(
    name: 'dev2.appwrite.io',
    type: Record::TYPE_NS,
    rdata: 'ns1.appwrite.io'
));

$resolver->addRecord(new Record(
    name: 'dev2.appwrite.io',
    type: Record::TYPE_NS,
    rdata: 'ns2.appwrite.io'
));

$resolver->addRecord(new Record(
    name: 'server.appwrite.io',
    type: Record::TYPE_SRV,
    rdata: 'server.appwrite.io',
    priority: 10,
    weight: 5,
    port: 25565
));

$resolver->addRecord(new Record(
    name: 'mail.appwrite.io',
    type: Record::TYPE_MX,
    rdata: 'mx.google.com',
    priority: 10
));

$resolver->addRecord(new Record(
    name: 'appwrite.io',
    type: Record::TYPE_SOA,
    ttl: 3600,
    rdata: 'ns1.appwrite.io. admin.appwrite.io. 2025011801 7200 3600 1209600 1800'
));

// Add a test zone apex for testing SOA inheritance
$resolver->addRecord(new Record(
    name: 'dnsservertestdomain.io',
    type: Record::TYPE_SOA,
    ttl: 7200,
    rdata: 'ns1.dnsservertestdomain.io. admin.dnsservertestdomain.io. 2025100601 86400 7200 3600000 172800'
));

$dns = new Server($server, $resolver);
$dns->setDebug(false);

$dns->start();
