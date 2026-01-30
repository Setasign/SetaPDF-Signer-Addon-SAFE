<?php

use setasign\SetaPDF\Signer\Module\SAFE\Client;
use Ramsey\Uuid\Uuid;

require_once '../vendor/autoload.php';

if (!file_exists('settings.php')) {
    echo 'The settings.php file is missing. See settings.php.dist for an example.';
    die();
}

$settings = require 'settings.php';
$apiUri = $settings['apiUri'];

$credentialId = $settings['credentialId'];
$processId = Uuid::uuid4()->toString();
$clientName = $settings['clientName'];

$httpClient = new GuzzleHttp\Client();
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


// uncomment this to create a new accessToken and update your settings.php with it

//var_dump($client->signatureAccountUpdateToken(
//    $settings['refreshToken'],
//    $credentialId,
//    $processId,
//    $clientName
//));
