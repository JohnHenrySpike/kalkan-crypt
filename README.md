## KalkanCrypt wrapper
[![PhpUnit](https://github.com/JohnHenrySpike/kalkan-crypt/actions/workflows/php.yml/badge.svg)](https://github.com/JohnHenrySpike/kalkan-crypt/actions/workflows/php.yml)

Wrapper for cryptographic library KalkanCrypt(PHP)

## Requirements
- PHP >= 8.2
- Composer
- KalkanCrypt extension (kalkancrypt.so) `for php-fpm use NTS version, for php-cli use TS version`


## Installation

Install the package with Composer:

    composer require johnhenryspike/kalkancrypt



## Examples

### 1. Using Provider::class
```php
$provider = new Provider();
return $provider->setKeyStore(new KeyStore('/path/to/keyStore.p12', 'password'))
    ->signData("Hello World", SignFlag::SIGN_CMS  | SignFlag::IN_PEM | SignFlag::OUT_PEM);
```

### 2. Using only Adapter::class
```php
$a = Adapter::getInstance();

$a -> loadKeyStore( Adapter::KCST_PKCS12, '/path/to/keyStore.p12', 'password');

// use if CA certs not registered in system
// $a -> loadCertFromFile(Adapter::KC_CERT_INTERMEDIATE, '/path/to/nca_gost.pem');
// $a -> loadCertFromFile(Adapter::KC_CERT_CA, '/path/to/root_gost.pem');

return $a -> signData( "Hello World", 
    Adapter::KC_SIGN_CMS | 
    Adapter::KC_IN_PEM   | 
    Adapter::KC_OUT_PEM 
);
```

### 3. Use Wsse client

```php
$req = [
    "requestInfo" => [
        "messageId" => "some_id",
        "serviceId" => "vshep_some_service",
        "messageDate" => date('c'),
        "sender" => [
            "senderId" => "some_login",
            "password" => "some_password"
        ],
    ],
    "requestData" => [
        "data" => [
            "SomeMethod" => [
                "iin" => "1234567890",
                "page" =>"1",
                "pageSize"=>"10"
            ]
        ]
    ]
];
$xml = ArrayToXml::convert($req, 'request', addXmlDeclaration: false);

$provider = new Provider();
$provider->setKeyStore(new KeyStore('/path/to/keyStore.p12', 'password'));
$provider->loadChain(tryLoad: true);
$options = [
    "location" => "http://192.168.1.1/bip-sync-wss-gost/",
    "uri" => "http://bip.bee.kz/SyncChannel/v10/Types",
    'proxy_host' => '127.0.0.1',
    'proxy_port' => 80
];

$soap_client = new WsseClient($provider, $options);
$response = $soap_client->SendMessage(new SoapVar($xml, XSD_ANYXML));
return json_encode($response)
```

