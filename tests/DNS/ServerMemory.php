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

$dns = new Server($server, $resolver);
$dns->setDebug(false);

$dns->start();
