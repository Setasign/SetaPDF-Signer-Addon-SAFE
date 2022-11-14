# SetaPDF-Signer-Addon-SAFE

This package offers a module for the SetaPDF-Signer component that allows you
to use the ["Serviço de Assinatura de Faturas Eletrónicas" (SAFE)](https://www.autenticacao.gov.pt/servi%C3%A7o-de-assinatura-de-faturas-eletr%C3%B3nicas-safe-)
of the Portuguese State to digital sign PDFs in pure PHP.

## Comments and notes on the implementation

- While the documentation says that the API conforms to the CSC API we noted several
  differences which makes it impossible to use our existing [CSC API module](https://github.com/Setasign/SetaPDF-Signer-Addon-CSC).
- As we do not understand or speak Portuguese while the official documentation is only
  available in Portuguese, we tried to implement the API based on an
  [automated translation](/docs/AMA%20-%20SAFE%20Documento%20de%20integração-EN.pdf)
  and the OpenAPI Specification definitions found on the projects official
  [GitHub repository](https://github.com/amagovpt/doc-SAFE/tree/main/api).
- We're also not able to authenticate as a Portuguese citizen and were dependent on
  users to provide test credentials/tokens.
- The hashing algorithm is fixated to SHA256 as per documentation and the information from the /credentials/info
  endpoint are ignored. 
- The /v2/ endpoints are currently not implemented.

## Requirements

You need to have credentials and a valid access token to the SAFE API endpoints. 

This package is developed and tested on PHP >= 8.0. Requirements of the
[SetaPDF-Signer](https://www.setasign.com/signer)
component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

We're using [PSR-17 (HTTP Factories)](https://www.php-fig.org/psr/psr-17/) and
[PSR-18 (HTTP Client)](https://www.php-fig.org/psr/psr-18/) for the requests. So you'll need an implementation of
these. We recommend using Guzzle.

```
    "require" : {
        "guzzlehttp/guzzle": "^7.0",
        "http-interop/http-factory-guzzle": "^1.0"
    }
```

## Installation
Add following to your composer.json:

```json
{
    "require": {
        "setasign/setapdf-signer-addon-safe": "^1.0"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

and execute `composer update`. You need to define the `repository` to resolve the dependency to the
[SetaPDF-Signer](https://www.setasign.com/signer) component
(see [here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md) for more details).

## Usage

All classes in this package are located in the namespace `setasign\SetaPDF\Signer\Module\SAFE`. See the [examples/](examples/) folder for
working examples.

### The `Client` class

This class is a kind of proxy class to the SAFE API. Its constructor requires the following arguments:

- `$apiUri` The base url of the api e.g. `https://pprsafe.autenticacao.gov.pt`
- `$basicAuthUsername` The username for HTTP Basic authentiaction
- `$basicAuthPassword` The password for HTTP Basic authentiaction
- `$httpClient` PSR-18 HTTP Client implementation.
- `$requestFactory` PSR-17 HTTP Factory implementation.
- `$streamFactory` PSR-17 HTTP Factory implementation.

If you need to call an endpoint which is not covered by a proxy method, you can use the `call(string $path, ?string $accessToken = null, array $inputData = [])` method.

### The `Module` class

This is the main module for the SetaPDF-Signer which implements the
[`SetaPDF_Signer_Signature_Module_ModuleInterface`](https://manuals.setasign.com/api-reference/setapdf/c/SetaPDF.Signer.Signature.Module.ModuleInterface) interface.

Internally it creates PAdES conforming signatures by using the [`SetaPDF_Signer_Signature_Module_PadesProxyTrait`](https://manuals.setasign.com/api-reference/setapdf/c/SetaPDF.Signer.Signature.Module.PadesProxyTrait).

Its constructor requires the following arguments:

- `$accessToken` - The access token which is passed with the custom header SAFEAuthorization.
- `$client` - An instance of the `Client` class.
- `$credentialId` - The id of the credentials (can be received as demoed in [list-credentials.php](examples/list-credentials.php))
- `$processId` - A process id (a new Globally Unique Identifier (GUID) for each invocation).
- `$clientName` - The value for the clientName field.

Additionally, the module offers a `setDocumentName()` method. This method allows you to define the document name related
to the hash send to the SAFE API. By default, the document name is set to "document.pdf".

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
