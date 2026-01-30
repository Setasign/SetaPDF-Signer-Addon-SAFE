<?php

declare(strict_types=1);

use Ramsey\Uuid\Uuid;
use setasign\SetaPDF\Signer\Module\SAFE\Batch;
use setasign\SetaPDF\Signer\Module\SAFE\Client;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Font\Type0\Subset as Type0Subset;
use setasign\SetaPDF2\Core\Reader\FileReader;
use setasign\SetaPDF2\Core\Reader\StringReader;
use setasign\SetaPDF2\Core\Writer\FileInterface;
use setasign\SetaPDF2\Core\Writer\FileWriter;
use setasign\SetaPDF2\Signer\Signature\Appearance\Dynamic as DynamicAppearance;
use setasign\SetaPDF2\Signer\Signature\Module\Pades;
use setasign\SetaPDF2\Signer\SignatureField;
use setasign\SetaPDF2\Signer\Signer;
use setasign\SetaPDF2\Signer\Timestamp\Module\Rfc3161\Curl as CurlTsModule;

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

/* This callback has to create/get and return the field instance that should be used for the signature.
 * It is also possible to add signature properties or create a field appearance in this callback.
 */
$callback = static function(
    $key,
    array $file,
    Signer $signer,
    Pades $padesModule,
    Document $document
): SignatureField {
    // set some signature properties
    $signer->setReason('Signature for document ' . basename($file['out']));
    $signer->setLocation('Test Environment');

    $appearance = new DynamicAppearance($padesModule);
//    // let's create a font instance to not use standard fonts (not embedded)
//    $font = new Type0Subset(
//        $document,
//        'assets/fonts/DejaVu/ttf/DejaVuSans.ttf'
//    );
//    // and pass it to the appearance module
//    $appearance->setFont($font);
    $signer->setAppearance($appearance);

    return $signer->addSignatureField(
        SignatureField::DEFAULT_FIELD_NAME,
        1,
        SignatureField::POSITION_LEFT_TOP,
        [
            'x' => 20,
            'y' => -20
        ],
        200,
        50
    );
};

/* If you need control over the temporary file which needs to be created during the signature process, you can
 * create another callback, that has to return a writer instance for this file.
 * NOTE: You need to clean up these files on your own!
 */
//$tempFileCallback = static function($key, $file): FileInterface {
//    return new FileWriter('output/tmp-' . $key);
//};

// If you want to add timestamps to the signautre you can pass an appropriate module like this:
$url = 'https://freetsa.org/tsr'; // UPDATE THIS TO THE SERVICE OF YOUR TRUST
$timestampModule = new CurlTsModule($url);
$batch->setTimestampModule($timestampModule);
$batch->getTrustedCertificates()
    ->addFromFile('assets/freetsa-cacert.pem'); // for LTV we need to add this root as a trusted root, too.

try {
    $batch->sign($files, true, $callback/*, $tempFileCallback*/);

} catch (setasign\SetaPDF2\Signer\ValidationRelatedInfo\Exception $e) {
    // If VRI (validation related information) cannot be resolved, let's check the logs:
    foreach ($batch->getVriLoggers() as $key => $logger) {
        foreach ($logger->getLogs() as $log) {
            echo str_repeat(' ', $log->getDepth() * 4);
            echo $log->getMessage() . "\n";
        }
    }
}
