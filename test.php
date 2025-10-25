<?php


include 'src/DNS/Client.php';
include 'src/DNS/Zone.php';
include 'src/DNS/Record.php';

use Utopia\DNS\Client;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Zone;

$client = new Client('8.8.8.8', 53);

$records = $client->query(new Question('appwrite.io', Record::TYPE_NS));

var_dump($records);
exit();

$zone = new Zone();

$domain = 'example.com';

var_dump('DigitalOcean');

$content = file_get_contents('tests/resources/zone-valid-digitalocean.txt');
$validate = $zone->validate($domain, $content);
var_dump($validate);
$validate = $zone->import($domain, $content);
var_dump(count($validate));

var_dump('Cloudflare');

$content = file_get_contents('tests/resources/zone-valid-cloudflare.txt');
$validate = $zone->validate($domain, $content);
var_dump($validate);
$validate = $zone->import($domain, $content);
var_dump(count($validate));

var_dump('Example.com');

$content = file_get_contents('tests/resources/zone-valid-example.com.txt');
$validate = $zone->validate($domain, $content);
var_dump($validate);
$validate = $zone->import($domain, $content);
var_dump(count($validate));

var_dump('RedHat');

$content = file_get_contents('tests/resources/zone-valid-redhat.txt');
$validate = $zone->validate($domain, $content);
var_dump($validate);
$validate = $zone->import($domain, $content);
var_dump(count($validate));


var_dump('Oracle 1');

$content = file_get_contents('tests/resources/zone-valid-oracle1.txt');
$validate = $zone->validate($domain, $content);
var_dump($validate);
$validate = $zone->import($domain, $content);
var_dump(count($validate));

var_dump('Oracle 2');

$content = file_get_contents('tests/resources/zone-valid-oracle2.txt');
$validate = $zone->validate($domain, $content);
var_dump($validate);
$validate = $zone->import($domain, $content);
var_dump(count($validate));

var_dump('Localhost');

$content = file_get_contents('tests/resources/zone-valid-localhost.txt');
$validate = $zone->validate($domain, $content);
var_dump($validate);
$validate = $zone->import($domain, $content);
var_dump(count($validate));


var_dump('Reverse localhost');

$content = file_get_contents('tests/resources/zone-valid-reverse.txt');
$validate = $zone->validate($domain, $content);
var_dump($validate);
$validate = $zone->import($domain, $content);
var_dump(count($validate));

var_dump($validate);
