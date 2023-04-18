<?php

require __DIR__ . '/../../vendor/autoload.php';

use Utopia\DNS\Server;
use Utopia\DNS\Adapter\Swoole;
use Utopia\DNS\Resolver\Mock;

$server = new Swoole('0.0.0.0', 53);
$resolver = new Mock();

$dns = new Server($server, $resolver);

$dns->start();
