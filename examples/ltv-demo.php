<?php

declare(strict_types=1);

use Ramsey\Uuid\Uuid;
use setasign\SetaPDF\Signer\Module\SAFE\Client;
use setasign\SetaPDF\Signer\Module\SAFE\Module;

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

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

$module = new Module($accessToken, $client, $credentialId, $processId, $settings['clientName']);
$module->setCertificate($certificate);
$module->setExtraCertificates($certificates);

// create a collection of trusted certificats:
$trustedCertificates = new SetaPDF_Signer_X509_Collection($certificates[count($certificates) - 1]);

// create a writer instance
$writer = new SetaPDF_Core_Writer_File($resultPath);
$tmpWriter = new SetaPDF_Core_Writer_TempFile();
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $tmpWriter);

// create the signer instance
$signer = new SetaPDF_Signer($document);

// add a signature field manually to get access to its name
$signatureField = $signer->addSignatureField();
// ...this is needed to add validation related information later
$signer->setSignatureFieldName($signatureField->getQualifiedName());

$signer->sign($module);

// create a new instance
$document = SetaPDF_Core_Document::loadByFilename($tmpWriter->getPath(), $writer);

// create a VRI collector instance
$collector = new SetaPDF_Signer_ValidationRelatedInfo_Collector($trustedCertificates);

// get VRI for the timestamp signature
$vriData = $collector->getByFieldName(
    $document,
    $signatureField->getQualifiedName()
);

//$logger = $collector->getLogger();
//foreach ($logger->getLogs() as $log) {
//    echo str_repeat(' ', $log->getDepth() * 4) . $log . "\n";
//}

// and add it to the document.
$dss = new SetaPDF_Signer_DocumentSecurityStore($document);
$dss->addValidationRelatedInfoByFieldName(
    $signatureField->getQualifiedName(),
    $vriData->getCrls(),
    $vriData->getOcspResponses(),
    $vriData->getCertificates()
);

// save and finish the final document
$document->save()->finish();

echo '<a href="data:application/pdf;base64,' . base64_encode(file_get_contents($resultPath)) . '" ' .
    'download="' . basename($resultPath) . '">download</a> | <a href="?">restart</a><br />';
