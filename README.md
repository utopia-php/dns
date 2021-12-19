# Utopia DNS

[![Build Status](https://travis-ci.org/utopia-php/dns.svg?branch=master)](https://travis-ci.com/utopia-php/dns)
![Total Downloads](https://img.shields.io/packagist/dt/utopia-php/dns.svg)
[![Discord](https://img.shields.io/discord/564160730845151244)](https://appwrite.io/discord)

Utopia DNS is a simple and lite abstraction layer for quickly setting up a DNS server. This library is aiming to be as simple and easy to learn and use. This library is maintained by the Appwrite team.

Although this library is part of the [Utopia Framework](https://github.com/utopia-php/framework) project it is dependency free, and can be used as standalone with any other PHP project or framework.

## Getting Started

Install using composer:
```bash
composer require utopia-php/dns
```

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

### Supported DNS Records

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

### Future Possibilities

Currently this library only support DNS over UDP. We could add support for both DNS over TLS and HTTPS. We should also add better support for query flags, and possibly create some more predefined resolvers.

## System Requirements

Utopia Framework requires PHP 8.0 or later. We recommend using the latest PHP version whenever possible.

## Authors

**Eldad Fux**

+ [https://twitter.com/eldadfux](https://twitter.com/eldadfux)
+ [https://github.com/eldadfux](https://github.com/eldadfux)

## Copyright and license

The MIT License (MIT) [http://www.opensource.org/licenses/mit-license.php](http://www.opensource.org/licenses/mit-license.php)
