# Utopia DNS

[![Tests](https://github.com/utopia-php/dns/actions/workflows/tests.yml/badge.svg)](https://github.com/utopia-php/dns/actions/workflows/tests.yml)
[![Packagist Version](https://img.shields.io/packagist/v/utopia-php/dns.svg)](https://packagist.org/packages/utopia-php/dns)
![Packagist Downloads](https://img.shields.io/packagist/dt/utopia-php/dns.svg)
[![Discord](https://img.shields.io/discord/564160730845151244)](https://appwrite.io/discord)

Utopia DNS is a modern PHP 8.3 toolkit for building DNS servers and clients. It provides a fully-typed DNS message encoder/decoder, pluggable resolvers, and telemetry hooks so you can stand up custom authoritative or proxy DNS services with minimal effort.

Although part of the [Utopia Framework](https://github.com/utopia-php/framework) family, the library is framework-agnostic and can be used in any PHP project.

## Installation

```bash
composer require utopia-php/dns
```

The library requires PHP 8.3+ with the `ext-sockets` extension. The Swoole adapter additionally needs the `ext-swoole` extension.

## Quick start

Create an authoritative DNS server by wiring an adapter (UDP socket implementation) and a resolver (how records are answered). The example below uses the native PHP socket adapter and the in-memory zone resolver.

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Utopia\DNS\Adapter\Native;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Resolver\Memory;
use Utopia\DNS\Server;
use Utopia\DNS\Zone;

$adapter = new Native('0.0.0.0', 5300);

$zone = new Zone(
    name: 'example.test',
    records: [
The server listens on UDP and TCP port `5300` (RFC 5966) and answers queries for `example.test` from the in-memory zone. Implement the [`Utopia\DNS\Resolver`](src/DNS/Resolver.php) interface to serve records from databases, APIs, or other stores.
        new Record(name: 'www.example.test', type: Record::TYPE_CNAME, rdata: 'example.test', ttl: 60),
        type: Record::TYPE_SOA,
        rdata: 'ns1.example.test hostmaster.example.test 1 7200 1800 1209600 3600',
        ttl: 60
    ),
);

$server = new Server($adapter, new Memory($zone));
$server->setDebug(true);

$server->start();
```

The server listens on UDP port `5300` and answers queries for `example.test` from the in-memory zone. Implement the [`Utopia\DNS\Resolver`](src/DNS/Resolver.php) interface to serve records from databases, APIs, or other stores.

## Resolvers
- `Memory`: authoritative resolver backed by a `Zone` object
- `Proxy`: forwards queries to another DNS server
- `Cloudflare`: proxy resolver preconfigured for `1.1.1.1` / `1.0.0.1`
- `Google`: proxy resolver preconfigured for `8.8.8.8` / `8.8.4.4`

Resolvers can be combined with any adapter. Implementing the `Resolver` interface allows you to plug in custom logic while reusing the message encoding/decoding and telemetry tooling.

## Adapters
- `Native`: pure PHP UDP server based on `ext-sockets`
- `Swoole`: non-blocking server built on the Swoole UDP runtime

Adapters are responsible only for receiving and returning raw packets. They call back into the server with the payload, source IP, and port so your resolver logic stays isolated.

## DNS client

The bundled client can query any DNS server and returns fully decoded messages.

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Utopia\DNS\Client;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;

$client = new Client('1.1.1.1');

$query = Message::query(
    new Question('example.com', Record::TYPE_A)
);

$response = $client->query($query);

foreach ($response->answers as $answer) {
    echo "{$answer->name} {$answer->ttl} {$answer->getTypeName()} {$answer->rdata}\n";
}
```

## Telemetry

`Server::setTelemetry()` accepts any adapter from [`utopia-php/telemetry`](https://github.com/utopia-php/telemetry). Counters (`dns.queries.total`, `dns.responses.total`) and a histogram (`dns.query.duration`) are emitted automatically, enabling Prometheus or OpenTelemetry pipelines with minimal configuration.

## Development
- Install dependencies: `composer install`
- Static analysis: `composer check`
- Coding standards: `composer lint` (use `composer format` to auto-fix)
- Tests: `composer test`
- Sample Swoole server for manual testing: `docker compose up`

## Benchmarking

Run the bundled benchmark tool to measure throughput against your server:

```bash
php tests/benchmark.php --server=127.0.0.1 --port=5300 --iterations=1000 --concurrency=20
```

The script reports requests per second, latency distribution, and error counts across common record types.

## License

MIT
