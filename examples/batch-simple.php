<?php

declare(strict_types=1);

use Ramsey\Uuid\Uuid;
use setasign\SetaPDF\Signer\Module\SAFE\Batch;
use setasign\SetaPDF\Signer\Module\SAFE\Client;
use setasign\SetaPDF2\Core\Reader\FileReader;
use setasign\SetaPDF2\Core\Reader\StringReader;

require_once(__DIR__ . '/../vendor/autoload.php');

if (!file_exists('settings.php')) {
    echo 'The settings.php file is missing. See settings.php.dist for an example.';
    die();
}

$settings = require 'settings.php';
$apiUri = $settings['apiUri'];

$fileToSign = __DIR__ . '/assets/camtown/Laboratory-Report.pdf';
$resultPath = 'signed.pdf';

$processId = Uuid::uuid4()->toString();
$accessToken = $settings['accessToken'];
$credentialId = $settings['credentialId'];

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

// fetch all information regarding your credential id like the certificates
$credentialInfo = $client->credentialsInfo($accessToken, $credentialId, $processId, $settings['clientName'], 'chain');
//echo '<pre>';
//var_dump($credentialInfo);
//echo '</pre>';

$certificates = $credentialInfo['cert']['certificates'];

// INFO: YOU SHOULD CACHE THE DATA IN $credentialInfo FOR LESS API REQUESTS

// the first certificate is always the signing certificate
$certificate = array_shift($certificates);

$batch = new Batch($accessToken, $client, $credentialId, $processId, $settings['clientName']);
$batch->setCertificate($certificate);
$batch->setExtraCertificates($certificates);
$batch->getTrustedCertificates()
    ->add($certificates[count($certificates) - 1]); // add the root certificate from the chain as trusted (needed for LTV)

// create a re-usable array of filenames (in/out)
$files = [
    [
        'in' => new FileReader('assets/tektown/Laboratory-Report.pdf'),
        'out' => 'output/tektown-signed.pdf'
    ],
    [
        'in' => new StringReader(file_get_contents('assets/lenstown/Laboratory-Report.pdf')),
        'out' => 'output/lenstown-signed.pdf'
    ],
    [
        'in' => 'assets/etown/Laboratory-Report.pdf',
        'out' => 'output/etown-signed.pdf'
    ],
    [
        'in' => 'assets/camtown/Laboratory-Report.pdf',
        'out' => 'output/camtown-signed.pdf'
    ],
];

$batch->sign($files);
