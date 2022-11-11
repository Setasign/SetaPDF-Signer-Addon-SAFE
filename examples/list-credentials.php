<?php

use setasign\SetaPDF\Signer\Module\SAFE\Client;
use Ramsey\Uuid\Uuid;

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once '../vendor/autoload.php';

$settings = require 'settings.php';
$apiUri = $settings['apiUri'];

$httpClient = new GuzzleHttp\Client();
$httpClient = new Mjelamanov\GuzzlePsr18\Client($httpClient);
$requestFactory = new Http\Factory\Guzzle\RequestFactory();
$streamFactory = new Http\Factory\Guzzle\StreamFactory();
$client = new Client(
    $apiUri,
    $settings['basicAuthUsername'],
    $settings['basicAuthPassword'],
    $httpClient,
    $requestFactory,
    $streamFactory
);

$list = $client->credentialsList($settings['accessToken'], Uuid::uuid4(), $settings['clientName']);

var_dump($list);
