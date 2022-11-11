<?php

namespace setasign\SetaPDF\Signer\Module\SAFE;

use SetaPDF_Core_Reader_FilePath;
use SetaPDF_Signer_Asn1_Element;
use SetaPDF_Signer_Asn1_Oid;
use SetaPDF_Signer_Digest;
use SetaPDF_Signer_Signature_DictionaryInterface;
use SetaPDF_Signer_Signature_DocumentInterface;
use SetaPDF_Signer_Signature_Module_ModuleInterface;
use SetaPDF_Signer_Signature_Module_PadesProxyTrait;

class Module implements
    SetaPDF_Signer_Signature_Module_ModuleInterface,
    SetaPDF_Signer_Signature_DictionaryInterface,
    SetaPDF_Signer_Signature_DocumentInterface
{
    use SetaPDF_Signer_Signature_Module_PadesProxyTrait;

    /**
     * @var Client
     */
    protected $client;

    /**
     * @var string
     */
    protected $accessToken;

    /**
     * @var string
     */
    protected $credentialId;
    protected $processId;
    protected $clientName;

    /**
     * Module constructor.
     *
     * @param string $accessToken
     * @param Client $client
     */
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

    public function createSignature(SetaPDF_Core_Reader_FilePath $tmpPath)
    {
        $hashAlgorithm = 'sha256'; // let's fixiate this for this example
        $padesModule = $this->_getPadesModule();
        $padesModule->setDigest($hashAlgorithm);

        $hashValue = hash($hashAlgorithm, $padesModule->getDataToSign($tmpPath), true);

        $digestInfo = new SetaPDF_Signer_Asn1_Element(
            SetaPDF_Signer_Asn1_Element::SEQUENCE | SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED, '',
            [
                new SetaPDF_Signer_Asn1_Element(
                    SetaPDF_Signer_Asn1_Element::SEQUENCE | SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED, '',
                    [
                        new SetaPDF_Signer_Asn1_Element(
                            SetaPDF_Signer_Asn1_Element::OBJECT_IDENTIFIER,
                            SetaPDF_Signer_Asn1_Oid::encode(
                                SetaPDF_Signer_Digest::getOid($padesModule->getDigest())
                            )
                        ),
                        new SetaPDF_Signer_Asn1_Element(SetaPDF_Signer_Asn1_Element::NULL)
                    ]
                ),
                new SetaPDF_Signer_Asn1_Element(
                    SetaPDF_Signer_Asn1_Element::OCTET_STRING,
                    $hashValue
                )
            ]
        );

        $hash = base64_encode($digestInfo);

        $sad = $this->client->credentialsAuthorize(
            $this->accessToken,
            $this->credentialId,
            ['test.pdf' => $hash],
            $this->processId,
            $this->clientName
        )['sad'];

        $signatureValue = $this->client->signaturesSignHash(
            $this->accessToken,
            $this->credentialId,
            $sad,
            [$hash],
            $this->processId,
            $this->clientName
        )[0];

        // pass the signature value to the CMS structure
        $padesModule->setSignatureValue(base64_decode($signatureValue));

        return (string)$padesModule->getCms();
    }
}
