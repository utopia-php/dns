<?php


include 'src/DNS/Zone.php';
include 'src/DNS/Record.php';

use Utopia\DNS\Zone;

$z = new Zone();

$domain = 'example.com';

var_dump('DigitalOcean');

$content = file_get_contents('tests/resources/zone-valid-digitalocean.txt');
$validate = $z->validateZoneFile($domain, $content);
var_dump($validate);
$validate = $z->import($domain, $content);
var_dump(count($validate));

var_dump('Cloudflare');

$content = file_get_contents('tests/resources/zone-valid-cloudflare.txt');
$validate = $z->validateZoneFile($domain, $content);
var_dump($validate);
$validate = $z->import($domain, $content);
var_dump(count($validate));

var_dump('Example.com');

$content = file_get_contents('tests/resources/zone-valid-example.com.txt');
$validate = $z->validateZoneFile($domain, $content);
var_dump($validate);
$validate = $z->import($domain, $content);
var_dump(count($validate));

var_dump('RedHat');

$content = file_get_contents('tests/resources/zone-valid-redhat.txt');
$validate = $z->validateZoneFile($domain, $content);
var_dump($validate);
$validate = $z->import($domain, $content);
var_dump(count($validate));


var_dump('Oracle 1');

$content = file_get_contents('tests/resources/zone-valid-oracle1.txt');
$validate = $z->validateZoneFile($domain, $content);
var_dump($validate);
$validate = $z->import($domain, $content);
var_dump(count($validate));

var_dump('Oracle 2');

$content = file_get_contents('tests/resources/zone-valid-oracle2.txt');
$validate = $z->validateZoneFile($domain, $content);
var_dump($validate);
$validate = $z->import($domain, $content);
var_dump(count($validate));

var_dump('Localhost');

$content = file_get_contents('tests/resources/zone-valid-localhost.txt');
$validate = $z->validateZoneFile($domain, $content);
var_dump($validate);
$validate = $z->import($domain, $content);
var_dump(count($validate));


var_dump('Reverse localhost');

$content = file_get_contents('tests/resources/zone-valid-reverse.txt');
$validate = $z->validateZoneFile($domain, $content);
var_dump($validate);
$validate = $z->import($domain, $content);
var_dump(count($validate));

var_dump($validate);