<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\SAFE;

use Psr\Http\Client\ClientExceptionInterface;
use SetaPDF_Signer_Asn1_Element;
use SetaPDF_Signer_Asn1_Oid;
use SetaPDF_Signer_Digest;
use SetaPDF_Signer_DocumentSecurityStore;
use SetaPDF_Signer_Timestamp_Module_ModuleInterface;
use SetaPDF_Signer_ValidationRelatedInfo_Collector;
use SetaPDF_Signer_ValidationRelatedInfo_LoggerInterface;
use SetaPDF_Signer_X509_Collection;

class Batch
{
    protected int $signatureConentLength = 28000;
    protected Client $client;
    protected string $accessToken;
    protected string $credentialId;
    protected string $processId;
    protected string $clientName;
    protected string|\SetaPDF_Signer_X509_Certificate $certificate;
    protected array|SetaPDF_Signer_X509_Collection $extraCertificates;
    protected SetaPDF_Signer_Timestamp_Module_ModuleInterface $timestampModule;
    protected SetaPDF_Signer_X509_Collection $trustedCertificates;
    /**
     * @var SetaPDF_Signer_ValidationRelatedInfo_LoggerInterface[]
     */
    protected array $vriLoggers;

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
        $this->trustedCertificates = new SetaPDF_Signer_X509_Collection();
    }

    /**
     * Set the signature content length that will be used to reserve space for the final signature.
     *
     * @param int $signatureContentLength The length of the signature content.
     */
    public function setSignatureContentLength(int $signatureContentLength): void
    {
        $this->signatureConentLength = $signatureContentLength;
    }

    /**
     * Get the signature content length that will be used to reserve space for the final signature.
     *
     * @return int
     */
    public function getSignatureContentLength(): int
    {
        return $this->signatureConentLength;
    }

    public function setCertificate(string|\SetaPDF_Signer_X509_Certificate $certificate): void
    {
        $this->certificate = $certificate;
    }

    /**
     * @param array|SetaPDF_Signer_X509_Collection $extraCertificates PEM encoded certificates or pathes to PEM encoded
     *                                                                certificates.
     * @return void
     */
    public function setExtraCertificates($extraCertificates): void
    {
        $this->extraCertificates = $extraCertificates;
    }

    public function getTrustedCertificates(): SetaPDF_Signer_X509_Collection
    {
        return $this->trustedCertificates;
    }

    public function setTimestampModule(SetaPDF_Signer_Timestamp_Module_ModuleInterface $timestampModule): void
    {
        $this->timestampModule = $timestampModule;
    }

    /**
     * @param array{in:string|\SetaPDF_Core_Reader_ReaderInterface, out: string|\SetaPDF_Core_Writer_WriterInterface, documentName: ?string}[] $files
     * @param bool $addLtv
     * @param callable|null $callback A callable which needs to have the following signature:
     *                                `function($key, array $file, SetaPDF_Signer $signer, SetaPDF_Signer_Signature_Module_Pades $padesModule, SetaPDF_Core_Document $document): SetaPDF_Signer_SignatureField`
     * @param callable|null $tmpFileCallback A callable which needs to have the following signature:
     *                                       `function($key, $file): SetaPDF_Core_Writer_FileInterface`
     * @return void
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws \JsonException
     * @throws \SetaPDF_Core_Exception
     * @throws \SetaPDF_Core_Parser_CrossReferenceTable_Exception
     * @throws \SetaPDF_Core_Parser_Pdf_InvalidTokenException
     * @throws \SetaPDF_Core_Reader_Exception
     * @throws \SetaPDF_Core_SecHandler_Exception
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @throws \SetaPDF_Signer_Exception
     * @throws \SetaPDF_Signer_Exception_ContentLength
     * @throws \SetaPDF_Signer_ValidationRelatedInfo_Exception
     */
    public function sign(array $files, bool $addLtv = true, callable $callback = null, callable $tmpFileCallback = null): void
    {
        if (!\is_callable($callback)) {
            $callback = static function($key, array $file, \SetaPDF_Signer $signer) {
                return $signer->addSignatureField();
            };
        }

        $data = [];
        $hashes = [];

        $no = 1;
        foreach ($files as $key => $file) {
            if (!$file['in'] instanceof \SetaPDF_Core_Reader_ReaderInterface) {
                $reader = new \SetaPDF_Core_Reader_File($file['in']);
            } else {
                $reader = $file['in'];
            }

            if (!$file['out'] instanceof \SetaPDF_Core_Writer_WriterInterface) {
                $writer = new \SetaPDF_Core_Writer_File($file['out']);
            } else {
                $writer = $file['out'];
            }

            if (\is_callable($tmpFileCallback)) {
                $tempWriter = $tmpFileCallback($key, $file);
            } else {
                $tempWriter = new \SetaPDF_Core_Writer_TempFile();
            }

            $document = \SetaPDF_Core_Document::load($reader, $writer);
            $signer = new \SetaPDF_Signer($document);
            $signer->setAllowSignatureContentLengthChange(false);
            $signer->setSignatureContentLength($this->getSignatureContentLength());

            $padesModule = new \SetaPDF_Signer_Signature_Module_Pades();
            $padesModule->setDigest(SetaPDF_Signer_Digest::SHA_256);
            $padesModule->setCertificate($this->certificate);
            $padesModule->setExtraCertificates($this->extraCertificates);

            $field = $callback($key, $file, $signer, $padesModule, $document);
            if (!$field instanceof \SetaPDF_Signer_SignatureField) {
                throw new \InvalidArgumentException('Callback does not return an instance of \SetaPDF_Signer_SignatureField.');
            }
            $fieldName = $field->getQualifiedName();
            $signer->setSignatureFieldName($fieldName);

            $tmpDocument = $signer->preSign($tempWriter, $padesModule);

            $hashValue = \hash($padesModule->getDigest(), $padesModule->getDataToSign($tmpDocument->getHashFile()), true);

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

            $hash = \base64_encode((string)$digestInfo);

            $data[] = [
                'document' => $document,
                'tmpDocument' => $tmpDocument,
                'signer' => $signer,
                'fieldName' => $fieldName,
                'padesModule' => $padesModule
            ];

            $documentName = $file['documentName'] ?? 'document-' . $no . '.pdf';
            if (isset($hashes[$documentName])) {
                throw new Exception('The field "documentName" needs to be unique.');
            }
            $hashes[$documentName] = $hash;
            $no++;
        }

        $this->client->v2CredentialsAuthorize(
            $this->accessToken,
            $this->credentialId,
            $hashes,
            $this->processId,
            $this->clientName
        );

        $sad = $this->client->credentialsAuthorizeVerify($this->processId)['sad'];

        $this->client->v2SignaturesSignHash(
            $this->accessToken,
            $this->credentialId,
            $sad,
            $hashes,
            $this->processId,
            $this->clientName
        );

        $vriData = null;
        foreach ($this->client->signaturesSignHashVerify($this->processId) as $key => $signatureValue) {
            /**
             * @var \SetaPDF_Core_Document $document
             * @var \SetaPDF_Signer_Signature_Module_Pades $padesModule
             * @var \SetaPDF_Signer $signer
             */
            $document = $data[$key]['document'];
            $padesModule = $data[$key]['padesModule'];
            $padesModule->setSignatureValue(\base64_decode($signatureValue));
            $signer = $data[$key]['signer'];
            // get the final CMS container
            $cms = (string)$padesModule->getCms();

            if (isset($this->timestampModule)) {
                $signer->setTimestampModule($this->timestampModule);
                $cms = $signer->addTimeStamp($cms, $data[$key]['tmpDocument']);
            }

            if ($addLtv) {
                $mainWriter = $document->getWriter();
                $tempWriter = new \SetaPDF_Core_Writer_TempFile();
                $document->setWriter($tempWriter);
            }

            // and pass it to the main signer instance
            $signer->saveSignature($data[$key]['tmpDocument'], $cms);

            if ($addLtv) {
                $document = \SetaPDF_Core_Document::loadByFilename($tempWriter->getPath(), $mainWriter);
                $fieldName = $data[$key]['fieldName'];

                // create a VRI collector instance
                $collector = new SetaPDF_Signer_ValidationRelatedInfo_Collector($this->trustedCertificates);
                $this->vriLoggers[] = $collector->getLogger();
                $vriData = $collector->getByFieldName(
                    $document,
                    $fieldName,
                    SetaPDF_Signer_ValidationRelatedInfo_Collector::SOURCE_OCSP_OR_CRL,
                    null,
                    null,
                    $vriData // reuse previously gathered information
                );

                $dss = new SetaPDF_Signer_DocumentSecurityStore($document);
                $dss->addValidationRelatedInfoByFieldName(
                    $fieldName,
                    $vriData->getCrls(),
                    $vriData->getOcspResponses(),
                    $vriData->getCertificates()
                );

                $document->save()->finish();
            }
        }
    }

    public function getVriLoggers(): array
    {
        return $this->vriLoggers;
    }
}
