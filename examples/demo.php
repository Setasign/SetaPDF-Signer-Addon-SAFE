<?php

declare(strict_types=1);

use Ramsey\Uuid\Uuid;
use setasign\SetaPDF\Signer\Module\SAFE\Client;
use setasign\SetaPDF\Signer\Module\SAFE\Module;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Writer\FileWriter;
use setasign\SetaPDF2\Signer\Signer;

require_once(__DIR__ . '/../vendor/autoload.php');

if (!file_exists('settings.php')) {
    echo 'The settings.php file is missing. See settings.php.dist for an example.';
    die();
}

$settings = require 'settings.php';
$apiUri = $settings['apiUri'];

$fileToSign = __DIR__ . '/assets/camtown/Laboratory-Report.pdf';
$resultPath = 'output/demo.pdf';

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

$module = new Module($accessToken, $client, $credentialId, $processId, $settings['clientName']);
$module->setCertificate($certificate);
$module->setExtraCertificates($certificates);
// specify a document name that is send to the API
$module->setDocumentName('my-document-name.pdf');

// create a writer instance
$writer = new FileWriter($resultPath);
// create the document instance
$document = Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new Signer($document);

$signer->sign($module);

echo '<a href="data:application/pdf;base64,' . base64_encode(file_get_contents($resultPath)) . '" ' .
    'download="' . basename($resultPath) . '">download</a> | <a href="?">restart</a><br />';
