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
    protected ClientInterface $httpClient;

    /**
     * @var RequestFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected RequestFactoryInterface $requestFactory;

    /**
     * @var StreamFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected StreamFactoryInterface $streamFactory;

    protected string $apiUri;
    protected string $basicAuthUsername;
    protected string $basicAuthPassword;
    protected ?array $info;

    /**
     * Client constructor.
     *
     * @param string $apiUri
     * @param string $basicAuthUsername
     * @param string $basicAuthPassword
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

    /**
     * @param string $path
     * @param string|null $accessToken
     * @param array $inputData
     * @return ?array
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws \JsonException
     */
    public function call(string $path, ?string $accessToken = null, array $inputData = []): ?array
    {
        if (\count($inputData) === 0) {
            $inputData = '{}';
        } else {
            $inputData = \json_encode($inputData, JSON_THROW_ON_ERROR);
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

        $body = (string) $response->getBody();
        if ($body === '') {
            return null;
        }

        return \json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws \JsonException
     */
    public function callGet(string $path, $data = []): array
    {
        $tries = 5;
        while ($tries-- > 0) {
            $request = (
            $this->requestFactory->createRequest('GET', $this->apiUri . $path . '?' . \http_build_query($data))
                ->withHeader('Authorization', 'Basic ' . \base64_encode($this->basicAuthUsername . ':' . $this->basicAuthPassword))
            );

            $response = $this->httpClient->sendRequest($request);
            $statusCode = $response->getStatusCode();
            if ($statusCode === 204) {
                \sleep(1);
                continue;
            }

            if ($response->getStatusCode() !== 200) {
                throw new Exception('Error on ' . $path . ': ' . $response->getBody());
            }

            return \json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        }

        throw new Exception('Endpoint ' . $path . ' still returns status code 204 after 5 tries.');
    }

    /**
     * @throws ClientExceptionInterface
     * @throws \JsonException
     * @throws Exception
     */
    public function info(): array
    {
        if (!isset($this->info)) {
            $this->info = $this->call('/info');
        }
        return $this->info;
    }

    /**
     * @throws ClientExceptionInterface
     * @throws \JsonException
     * @throws Exception
     */
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

    /**
     * @throws ClientExceptionInterface
     * @throws \JsonException
     * @throws Exception
     */
    public function credentialsInfo(
        string $accessToken,
        string $credentialID,
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

    /**
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws \JsonException
     */
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

        return $this->call('/credentials/authorize', $accessToken, $inputData);
    }

    /**
     * @throws ClientExceptionInterface
     * @throws \JsonException
     * @throws Exception
     */
    public function v2credentialsAuthorize(
        string $accessToken,
        string $credentialID,
        array $hashes,
        string $processId,
        string $clientName
    ): bool {
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

        return $this->call('/v2/credentials/authorize', $accessToken, $inputData) === null;
    }

    /**
     * @throws Exception
     * @throws \JsonException
     */
    public function credentialsAuthorizeVerify(string $processId)
    {
        return $this->callGet('/credentials/authorize/verify', ['processId' => $processId]);
    }

    /**
     * @throws ClientExceptionInterface
     * @throws \JsonException
     * @throws Exception
     */
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
            'hashes' => \array_values($hashes),
            'signAlgo' => '1.2.840.113549.1.1.11',
            'clientData' => [
                'processId' => $processId,
                'clientName' => $clientName
            ]
        ];

        return $this->call('/signatures/signHash', $accessToken, $inputData)['signatures'];
    }

    /**
     * @throws ClientExceptionInterface
     * @throws \JsonException
     * @throws Exception
     */
    public function v2signaturesSignHash(
        string $accessToken,
        string $credentialID,
        string $sad,
        array $hashes,
        string $processId,
        string $clientName
    ): bool {
        $inputData = [
            'credentialID' => $credentialID,
            'sad' => $sad,
            'hashes' => \array_values($hashes),
            'signAlgo' => '1.2.840.113549.1.1.11',
            'clientData' => [
                'processId' => $processId,
                'clientName' => $clientName
            ]
        ];

        return $this->call('/v2//signatures/signHash', $accessToken, $inputData) === null;
    }


    /**
     * @throws Exception
     * @throws \JsonException
     */
    public function signaturesSignHashVerify(string $processId)
    {
        return $this->callGet('/signatures/signHash/verify', ['processId' => $processId])['signatures'];
    }

    /**
     * @throws ClientExceptionInterface
     * @throws \JsonException
     * @throws Exception
     */
    public function signatureAccountUpdateToken(
        string $refreshToken,
        string $credentialID,
        string $processId,
        string $clientName
    ): array {
        $inputData = [
            'credentialID' => $credentialID,
            'clientData' => [
                'processId' => $processId,
                'clientName' => $clientName
            ]
        ];

        return $this->call('/signatureAccount/updateToken', $refreshToken, $inputData);
    }
}
