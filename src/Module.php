<?php

namespace setasign\SetaPDF\Signer\Module\SAFE;

use Psr\Http\Client\ClientExceptionInterface;
use setasign\SetaPDF2\Core\Reader\FilePath;
use setasign\SetaPDF2\Signer\Asn1\Element as Asn1Element;
use setasign\SetaPDF2\Signer\Asn1\Oid as Asn1Oid;
use setasign\SetaPDF2\Signer\Digest;
use setasign\SetaPDF2\Signer\Signature\Module\DictionaryInterface;
use setasign\SetaPDF2\Signer\Signature\Module\DocumentInterface;
use setasign\SetaPDF2\Signer\Signature\Module\ModuleInterface;
use setasign\SetaPDF2\Signer\Signature\Module\PadesProxyTrait;

class Module implements
    ModuleInterface,
    DictionaryInterface,
    DocumentInterface
{
    use PadesProxyTrait;

    protected Client $client;
    protected string $accessToken;
    protected string $credentialId;
    protected string $processId;
    protected string $clientName;
    protected string $documentName = 'document.pdf';

    public function __construct(
        string $accessToken,
        Client $client,
        string $credentialId,
        string $processId,
        string $clientName
    ) {
        $this->accessToken = $accessToken;
        $this->client = $client;

        $this->credentialId = $credentialId;
        $this->processId = $processId;
        $this->clientName = $clientName;
    }

    public function setDocumentName(string $documentName): void
    {
        $this->documentName = $documentName;
    }

    /**
     * @param FilePath $tmpPath
     * @return string
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws \JsonException
     * @throws \setasign\SetaPDF2\Signer\Exception
     */
    public function createSignature(FilePath $tmpPath): string
    {
        $hashAlgorithm = 'sha256';
        $padesModule = $this->_getPadesModule();
        $padesModule->setDigest($hashAlgorithm);

        $hashValue = \hash($hashAlgorithm, $padesModule->getDataToSign($tmpPath), true);

        $digestInfo = new Asn1Element(
            Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED, '',
            [
                new Asn1Element(
                    Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED, '',
                    [
                        new Asn1Element(
                            Asn1Element::OBJECT_IDENTIFIER,
                            Asn1Oid::encode(
                                Digest::getOid($padesModule->getDigest())
                            )
                        ),
                        new Asn1Element(Asn1Element::NULL)
                    ]
                ),
                new Asn1Element(
                    Asn1Element::OCTET_STRING,
                    $hashValue
                )
            ]
        );

        $hash = \base64_encode($digestInfo);

        $this->client->v2CredentialsAuthorize(
            $this->accessToken,
            $this->credentialId,
            [$this->documentName => $hash],
            $this->processId,
            $this->clientName
        );

        $sad = $this->client->credentialsAuthorizeVerify($this->processId)['sad'];

        $this->client->v2SignaturesSignHash(
            $this->accessToken,
            $this->credentialId,
            $sad,
            [$hash],
            $this->processId,
            $this->clientName
        );

        $signatureValue = $this->client->signaturesSignHashVerify($this->processId)[0];

            // pass the signature value to the CMS structure
        $padesModule->setSignatureValue(\base64_decode($signatureValue));

        return (string)$padesModule->getCms();
    }
}
