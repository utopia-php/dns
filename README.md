# Utopia DNS

[![Build Status](https://travis-ci.org/utopia-php/dns.svg?branch=master)](https://travis-ci.com/utopia-php/dns)
![Total Downloads](https://img.shields.io/packagist/dt/utopia-php/dns.svg)
[![Discord](https://img.shields.io/discord/564160730845151244)](https://appwrite.io/discord)

Utopia DNS is a simple and lite abstraction layer for quickly setting up a DNS server. This library is aiming to be as simple and easy to learn and use. This library is maintained by the Appwrite team.

Although this library is part of the [Utopia Framework](https://github.com/utopia-php/framework) project it is dependency free, and can be used as standalone with any other PHP project or framework.

## Getting started

Install using composer:
```bash
composer require utopia-php/dns
```

## Using the DNS server

Init your DNS server with your preferred adapter and resolver. The adapter is used for running the UDP server to serve DNS requests, and the resolver will be used to answering DNS queries with proper results. You can and in most cases should implement your own resolver by extending [src/DNS/Resolver.php](src/DNS/Resolver.php)

```php
<?php

require_once __DIR__.'/init.php';

use Appwrite\DNS\Server;
use Appwrite\DNS\Adapter\Swoole;
use Appwrite\DNS\Resolver\Mock;

$server = new Swoole('0.0.0.0', 8000); // Swoole based UDP server running on port 8000
$resolver = new Mock(); // Mock resolver. Always returns 127.0.0.1 as the result

$dns = new Server($server, $resolver);

$dns->start();
```

## Using the DNS client

Utopia DNS also provides a simple, dependency‑free DNS client that can be used to perform queries against any DNS server. This client is ideal for applications that need to look up records on demand. It supports querying all sorts of DNS records (A, MX, TXT, AAAA, SRV, etc.).

Example Usage

Below is an example of how to use the DNS client:

```php 
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Utopia\DNS\Client;

$client = new Client('8.8.8.8'); // Query against Google's public DNS

try {
    // Query for A records for example.com
    $records = $client->query('example.com', 'A');
    
    foreach ($records as $record) {
        echo 'Name: '   . $record->getName()   . "\n";
        echo 'Type: '   . $record->getTypeName() . "\n";
        echo 'TTL: '    . $record->getTTL()      . "\n";
        echo 'Data: '   . $record->getRdata()    . "\n\n";
    }
    
    // Query for other record types (e.g. MX, TXT, AAAA, SRV)
    // $mxRecords = $client->query('example.com', 'MX');
    // $txtRecords = $client->query('example.com', 'TXT');
    // ...
    
} catch (Exception $e) {
    echo "DNS query failed: " . $e->getMessage();
}
```

### How it works

#### Instantiate the client

Create a new instance of the Client class and specify the DNS server you wish to query. In the example above, we use Google’s DNS server (8.8.8.8).

#### Perform a query

Use the query() method with the desired domain and record type (for example, 'A' for an IPv4 address) to retrieve DNS records.

The client returns an array of Record objects. These objects contain the queried domain name, type (both numeric and human‑readable), TTL, and record data.
Optional fields (such as priority, weight, and port for MX and SRV records) are available via their getters.

#### Error handling

The query is wrapped in a try‑catch block to handle any exceptions that may occur during the DNS lookup.

## Supported DNS records

* A
* NS
* CNAME
* SOA
* WKS
* PTR
* HINFO
* MX
* TXT
* RP
* SIG
* KEY
* LOC
* NXT
* AAAA
* CERT
* A6
* AXFR
* IXFR
* *

### Adapters

Below is a list of supported server adapters, and their compatibly tested versions alongside a list of supported features and relevant limits.

| Adapter | Status | Info | Version |
|---------|---------|---|---|
| Native | ✅ | A native PHP Socket | 8.0 |
| Swoole | ✅ | PHP Swoole UDP Server | 4.8.4 |
| Workerman | 🛠 | - | - |
| ReactPHP | 🛠 | - | - |

` ✅  - supported, 🛠  - work in progress`

### Future possibilities

Currently this library only support DNS over UDP. We could add support for both DNS over TLS and HTTPS. We should also add better support for query flags, and possibly create some more predefined resolvers.

## System requirements

Utopia Framework requires PHP 8.0 or later. We recommend using the latest PHP version whenever possible.

## Running tests

Run tests for this library using the provided Docker container.

```sh
docker compose exec -t dns-server vendor/bin/phpunit --configuration phpunit.xml
```
