<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\SAFE;

use Psr\Http\Client\ClientExceptionInterface;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Document\ObjectNotDefinedException;
use setasign\SetaPDF2\Core\Document\ObjectNotFoundException;
use setasign\SetaPDF2\Core\Exception;
use setasign\SetaPDF2\Core\Parser\Pdf\InvalidTokenException;
use setasign\SetaPDF2\Core\Reader\FileReader;
use setasign\SetaPDF2\Core\Reader\ReaderInterface;
use setasign\SetaPDF2\Core\Writer\FileWriter;
use setasign\SetaPDF2\Core\Writer\TempFileWriter;
use setasign\SetaPDF2\Core\Writer\WriterInterface;
use setasign\SetaPDF2\NotImplementedException;
use setasign\SetaPDF2\Signer\Asn1\Element as Asn1Element;
use setasign\SetaPDF2\Signer\Asn1\Oid as Asn1Oid;
use setasign\SetaPDF2\Signer\Digest;
use setasign\SetaPDF2\Signer\DocumentSecurityStore;
use setasign\SetaPDF2\Signer\Exception\ContentLength;
use setasign\SetaPDF2\Signer\Signature\Module\Pades;
use setasign\SetaPDF2\Signer\SignatureField;
use setasign\SetaPDF2\Signer\Signer;
use setasign\SetaPDF2\Signer\Timestamp\Module\ModuleInterface as TsModuleInterface;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\Collector;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\LoggerInterface;
use setasign\SetaPDF2\Signer\X509\Collection;
use setasign\SetaPDF2\Signer\X509\Certificate;

class Batch
{
    protected int $signatureConentLength = 28000;
    protected Client $client;
    protected string $accessToken;
    protected string $credentialId;
    protected string $processId;
    protected string $clientName;
    protected string|Certificate $certificate;
    protected array|Collection $extraCertificates;
    protected TsModuleInterface $timestampModule;
    protected Collection $trustedCertificates;
    /**
     * @var LoggerInterface[]
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
        $this->trustedCertificates = new Collection();
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

    public function setCertificate(string|Certificate $certificate): void
    {
        $this->certificate = $certificate;
    }

    /**
     * @param array|Collection $extraCertificates PEM encoded certificates or pathes to PEM encoded
     *                                                                certificates.
     * @return void
     */
    public function setExtraCertificates($extraCertificates): void
    {
        $this->extraCertificates = $extraCertificates;
    }

    public function getTrustedCertificates(): Collection
    {
        return $this->trustedCertificates;
    }

    public function setTimestampModule(TsModuleInterface $timestampModule): void
    {
        $this->timestampModule = $timestampModule;
    }

    /**
     * @param array{in:string|ReaderInterface, out: string|WriterInterface, documentName: ?string}[] $files
     * @param bool $addLtv
     * @param callable|null $callback A callable which needs to have the following signature:
     *                                `function($key, array $file, setasign\SetaPDF2\Signer\Signer $signer, setasign\SetaPDF2\Signer\Signature\Module\Pades $padesModule, setasign\SetaPDF2\Core\Document $document): setasign\SetaPDF2\Signer\SignatureField`
     * @param callable|null $tmpFileCallback A callable which needs to have the following signature:
     *                                       `function($key, $file): setasign\SetaPDF2\Core\Writer\FileInterface`
     * @return void
     * @throws ObjectNotDefinedException
     * @throws ObjectNotFoundException
     * @throws Exception
     * @throws \JsonException
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws \setasign\SetaPDF2\Core\Parser\CrossReferenceTable\Exception
     * @throws \setasign\SetaPDF2\Core\Parser\Exception
     * @throws InvalidTokenException
     * @throws \setasign\SetaPDF2\Core\Reader\Exception
     * @throws \setasign\SetaPDF2\Core\SecHandler\Exception
     * @throws \setasign\SetaPDF2\Core\Type\Exception
     * @throws \setasign\SetaPDF2\Core\Type\IndirectReference\Exception
     * @throws \setasign\SetaPDF2\Exception
     * @throws NotImplementedException
     * @throws \setasign\SetaPDF2\Signer\Asn1\Exception
     * @throws \setasign\SetaPDF2\Signer\Exception
     * @throws ContentLength
     * @throws \setasign\SetaPDF2\Signer\ValidationRelatedInfo\Exception
     */
    public function sign(array $files, bool $addLtv = true, callable $callback = null, callable $tmpFileCallback = null): void
    {
        if (!\is_callable($callback)) {
            $callback = static function($key, array $file, Signer $signer) {
                return $signer->addSignatureField();
            };
        }

        $data = [];
        $hashes = [];

        $no = 1;
        foreach ($files as $key => $file) {
            if (!$file['in'] instanceof ReaderInterface) {
                $reader = new FileReader($file['in']);
            } else {
                $reader = $file['in'];
            }

            if (!$file['out'] instanceof WriterInterface) {
                $writer = new FileWriter($file['out']);
            } else {
                $writer = $file['out'];
            }

            if (\is_callable($tmpFileCallback)) {
                $tempWriter = $tmpFileCallback($key, $file);
            } else {
                $tempWriter = new TempFileWriter();
            }

            $document = Document::load($reader, $writer);
            $signer = new Signer($document);
            $signer->setAllowSignatureContentLengthChange(false);
            $signer->setSignatureContentLength($this->getSignatureContentLength());

            $padesModule = new Pades();
            $padesModule->setDigest(Digest::SHA_256);
            $padesModule->setCertificate($this->certificate);
            $padesModule->setExtraCertificates($this->extraCertificates);

            $field = $callback($key, $file, $signer, $padesModule, $document);
            if (!$field instanceof SignatureField) {
                throw new \InvalidArgumentException('Callback does not return an instance of setasign\SetaPDF2\Signer\SignatureField.');
            }
            $fieldName = $field->getQualifiedName();
            $signer->setSignatureFieldName($fieldName);

            $tmpDocument = $signer->preSign($tempWriter, $padesModule);

            $hashValue = \hash($padesModule->getDigest(), $padesModule->getDataToSign($tmpDocument->getHashFile()), true);

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
             * @var Document $document
             * @var Pades $padesModule
             * @var Signer $signer
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
                $tempWriter = new TempFileWriter();
                $document->setWriter($tempWriter);
            }

            // and pass it to the main signer instance
            $signer->saveSignature($data[$key]['tmpDocument'], $cms);

            if ($addLtv) {
                $document = Document::loadByFilename($tempWriter->getPath(), $mainWriter);
                $fieldName = $data[$key]['fieldName'];

                // create a VRI collector instance
                $collector = new Collector($this->trustedCertificates);
                $this->vriLoggers[] = $collector->getLogger();
                $vriData = $collector->getByFieldName(
                    $document,
                    $fieldName,
                    Collector::SOURCE_OCSP_OR_CRL,
                    null,
                    null,
                    $vriData // reuse previously gathered information
                );

                $dss = new DocumentSecurityStore($document);
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
