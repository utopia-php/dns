<?php

require __DIR__ . '/../../vendor/autoload.php';

use Utopia\DNS\Server;
use Utopia\DNS\Adapter\Swoole;
use Utopia\DNS\Resolver\Memory;

$server = new Swoole('0.0.0.0', 53);
$resolver = new Memory();

$resolver->addRecord('dev.appwrite.io', 'A', [
    'value' => '180.12.3.24',
    'ttl' => 10
]);

$resolver->addRecord('dev2.appwrite.io', 'A', [
    'value' => '142.6.0.1'
]);
$resolver->addRecord('dev2.appwrite.io', 'A', [
    'value' => '142.6.0.2'
]);

$resolver->addRecord('dev.appwrite.io', 'AAAA', [
    'value' => '2001:0db8:0000:0000:0000:ff00:0042:8329',
    'ttl' => 20
]);

$resolver->addRecord('dev2.appwrite.io', 'AAAA', [
    'value' => '2001:0db8:0000:0000:0000:ff00:0000:0001'
]);

$resolver->addRecord('dev2.appwrite.io', 'AAAA', [
    'value' => '2001:0db8:0000:0000:0000:ff00:0000:0002'
]);

$resolver->addRecord('dev.appwrite.io', 'CNAME', [
    'value' => 'cloud.appwrite.io',
    'ttl' => 30
]);

$resolver->addRecord('dev2.appwrite.io', 'CNAME', [
    'value' => 'eu.cloud.appwrite.io'
]);

$resolver->addRecord('dev2.appwrite.io', 'CNAME', [
    'value' => 'us.cloud.appwrite.io'
]);

$resolver->addRecord('dev.appwrite.io', 'TXT', [
    'value' => 'awesome-secret-key',
    'ttl' => 40
]);

$resolver->addRecord('dev2.appwrite.io', 'TXT', [
    'value' => 'key with "$\'- symbols'
]);

$resolver->addRecord('dev2.appwrite.io', 'TXT', [
    'value' => 'key with spaces'
]);

$resolver->addRecord('dev2.appwrite.io', 'TXT', [
    'value' => 'v=DMARC1; p=none; rua=mailto:jon@snow.got; ruf=mailto:jon@snow.got; fo=1;'
]);

$resolver->addRecord('dev.appwrite.io', 'CAA', [
    'value' => 'issue "letsencrypt.org"',
    'ttl' => 50
]);

$resolver->addRecord('dev2.appwrite.io', 'CAA', [
    'value' => 'issue "letsencrypt.org"'
]);

$resolver->addRecord('dev2.appwrite.io', 'CAA', [
    'value' => 'issue "sectigo.com"'
]);

$resolver->addRecord('dev3.appwrite.io', 'CAA', [
    'value' => '255 issuewild "certainly.com;validationmethods=tls-alpn-01;retrytimeout=3600"'
]);

$resolver->addRecord('dev.appwrite.io', 'NS', [
    'value' => 'ns.appwrite.io',
    'ttl' => 60
]);

$resolver->addRecord('dev2.appwrite.io', 'NS', [
    'value' => 'ns1.appwrite.io'
]);

$resolver->addRecord('dev2.appwrite.io', 'NS', [
    'value' => 'ns2.appwrite.io'
]);

$resolver->addRecord('server.appwrite.io', 'SRV', [
    'value' => 'server.appwrite.io',
    'priority' => 10,
    'weight' => 5,
    'port' => 25565
]);

$resolver->addRecord('mail.appwrite.io', 'MX', [
    'value' => 'mx.google.com',
    'priority' => 10
]);

$resolver->addRecord('appwrite.io', 'SOA', [
    'value' => 'ns1.appwrite.io. admin.appwrite.io. 2025011801 7200 3600 1209600 1800',
    'ttl' => 3600
]);

$resolver->addRecord('dev2.appwrite.io', 'SOA', [
    'value' => 'ns1.dev2.appwrite.io. admin.dev2.appwrite.io. 2025011802 14400 7200 2419200 3600'
]);

$dns = new Server($server, $resolver);
$dns->setDebug(false);

$dns->start();
