<?php
// This is a simple test script to manually test the v2 signature flow.

declare(strict_types=1);

use Ramsey\Uuid\Uuid;
use setasign\SetaPDF\Signer\Module\SAFE\Client;

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once(__DIR__ . '/../vendor/autoload.php');

$settings = require 'settings.php';
$apiUri = $settings['apiUri'];

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

$a = $client->v2CredentialsAuthorize(
    $accessToken,
    $credentialId,
    $hashes = [
        'test.pdf' => base64_encode("\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20" . hash('sha256', 'test', true))
    ],
    $processId,
    $settings['clientName']
);
var_dump($a);
//sleep(1);

$sad = $client->credentialsAuthorizeVerify($processId)['sad'];
var_dump($sad);

$b = $client->v2SignaturesSignHash(
    $accessToken,
    $credentialId,
    $sad,
    $hashes,
    $processId,
    $settings['clientName']
);

var_dump($b);

$signatures = $client->signaturesSignHashVerify($processId);
var_dump($signatures);
