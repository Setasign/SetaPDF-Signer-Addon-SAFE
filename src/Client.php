<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\SAFE;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

class Client
{
    /**
     * @var ClientInterface PSR-18 HTTP Client implementation.
     */
    protected $httpClient;

    /**
     * @var RequestFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected $requestFactory;

    /**
     * @var StreamFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected $streamFactory;

    /**
     * @var string
     */
    protected $apiUri;

    /**
     * @var string
     */
    protected $basicAuthUsername;

    /**
     * @var string
     */
    protected $basicAuthPassword;

    /**
     * @var array|null
     */
    protected $info;

    /**
     * Client constructor.
     *
     * @param string $apiUri
     * @param ClientInterface $httpClient PSR-18 HTTP Client implementation.
     * @param RequestFactoryInterface $requestFactory PSR-17 HTTP Factory implementation.
     * @param StreamFactoryInterface $streamFactory PSR-17 HTTP Factory implementation.
     */
    public function __construct(
        string $apiUri,
        string $basicAuthUsername,
        string $basicAuthPassword,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory
    ) {
        $this->apiUri = $apiUri;
        $this->basicAuthUsername = $basicAuthUsername;
        $this->basicAuthPassword = $basicAuthPassword;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
    }

    public function setAccessToken(string $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Helper method to handle errors in json_decode
     *
     * @param string $json
     * @param bool $assoc
     * @param int $depth
     * @param int $options
     * @return mixed
     * @throws Exception
     */
    protected function json_decode(string $json, bool $assoc = true, int $depth = 512, int $options = 0)
    {
        // Clear json_last_error()
        \json_encode(null);

        $data = @\json_decode($json, $assoc, $depth, $options);

        if (\json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception(\sprintf(
                'Unable to decode JSON: %s',
                \json_last_error_msg()
            ));
        }

        return $data;
    }

    /**
     * @param string $path
     * @param string|null $accessToken
     * @param array $inputData
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function call(string $path, ?string $accessToken = null, array $inputData = []): array
    {
        if (count($inputData) === 0) {
            $inputData = '{}';
        } else {
            $inputData = \json_encode($inputData);
        }

        $request = (
        $this->requestFactory->createRequest('POST', $this->apiUri . $path)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Authorization', 'Basic ' . \base64_encode($this->basicAuthUsername . ':' . $this->basicAuthPassword))
            ->withBody($this->streamFactory->createStream($inputData))
        );

        if ($accessToken !== null) {
            $request = $request->withHeader('SAFEAuthorization', 'Bearer ' . $accessToken);
        }

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on ' . $path . ': ' . $response->getBody());
        }

        return $this->json_decode((string) $response->getBody());
    }

    /**
     * @param string|null $lang
     * @return array
     * @throws ClientExceptionInterface
     */
    public function info(?string $lang = null): array
    {
        if ($this->info === null || !\array_key_exists($lang, $this->info)) {
            $inputData = [];
            if ($lang !== null) {
                $inputData['lang'] = $lang;
            }
            $this->info[$lang ?? 'none'] = $this->call('/info', null, $inputData);
        }
        return $this->info[$lang ?? 'none'];
    }

    public function credentialsList(
        string $accessToken,
        string $processId,
        string $clientName
    ): array {
        return $this->call('/credentials/list', $accessToken, [
            'clientData' => [
                'processId' => $processId,
                'clientName' => $clientName
            ]
        ]);
    }

    public function credentialsInfo(
        string $accessToken,
        string $credentialID = null,
        string $processId,
        string $clientName,
        ?string $certificates = null
    ): array {
        $inputData = [
            'credentialID' => $credentialID,
            'clientData' => [
                'processId' => $processId,
                'clientName' => $clientName
            ]
        ];
        if ($certificates !== null) {
            $inputData['certificates'] = $certificates;
        }

        return $this->call('/credentials/info', $accessToken, $inputData);
    }

    public function credentialsAuthorize(
        string $accessToken,
        string $credentialID,
        array $hashes,
        string $processId,
        string $clientName
    ): array {
        $inputData = [
            'numSignatures' => \count($hashes),
            'hashes' => \array_values($hashes),
            'credentialID' => $credentialID,
            'clientData' => [
                'processId' => $processId,
                'clientName' => $clientName,
                'documentNames' => \array_keys($hashes),
            ]
        ];

        echo "<pre>";
        var_dump($inputData);
        echo "</pre>";

        return $this->call('/credentials/authorize', $accessToken, $inputData);
    }

    public function signaturesSignHash(
        string $accessToken,
        string $credentialID,
        string $sad,
        array $hashes,
        string $processId,
        string $clientName
    ): array {
        $inputData = [
            'credentialID' => $credentialID,
            'sad' => $sad,
            'hashes' => array_values($hashes),
            'signAlgo' => '1.2.840.113549.1.1.11',
            'clientData' => [
                'processId' => $processId,
                'clientName' => $clientName
            ]
        ];

        return $this->call('/signatures/signHash', $accessToken, $inputData)['signatures'];
    }
}
