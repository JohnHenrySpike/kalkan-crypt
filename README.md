## KalkanCrypt wrapper
[![PhpUnit](https://github.com/JohnHenrySpike/kalkan-crypt/actions/workflows/php.yml/badge.svg)](https://github.com/JohnHenrySpike/kalkan-crypt/actions/workflows/php.yml)
![Packagist Version](https://img.shields.io/packagist/v/JohnHenrySpike/kalkancrypt)
![Packagist Downloads](https://img.shields.io/packagist/dt/johnhenryspike/kalkancrypt)
![Packagist Stars](https://img.shields.io/packagist/stars/johnhenryspike/kalkancrypt)


Wrapper for cryptographic library KalkanCrypt(PHP)

## Requirements
- PHP >= 8.2
- Composer
- libs ( libltdl-dev, libpcsclite-dev, libxml2-dev ) 
- KalkanCrypt extension (kalkancrypt.so)


## Installation

Install the package with Composer:

    composer require johnhenryspike/kalkancrypt

## Examples

### 1. Basic usage
- load chain with intermediate and ca certificates registered in system
```php
// init KeyStore (default storage type PKCS12)
$keyStore = KeyStore::load('/path/to/keyStore.p12', 'password');
//init Chain 
$chain = Chain::init($this->keyStore)->fromSystem();
//init Provider with chain, sign data and return signed string
return Provider::init($chain)->signData("Hello world", SignFlag::SIGN_CMS | SignFlag::OUT_PEM);
```
- load chain from collection of intermediate and ca certificates
```php
$keyStore = KeyStore::load('/path/to/keyStore.p12', 'password');
$collection = new CertCollection();
$collection->addItem(Certificate::loadFromPath('/path/to/nca.cer'));
$collection->addItem(Certificate::loadFromPath('/path/to/root.cer'));
$chain = Chain::init($this->keyStore)->fromCollection($collection);
return Provider::init($chain)->signData("Hello world", SignFlag::SIGN_CMS | SignFlag::OUT_PEM);
```
- autoload chain from auth info
```php
$keyStore = KeyStore::load('/path/to/keyStore.p12', 'password');
$chain  = Chain::init($keyStore)->fromAuthInfo();
return Provider::init($chain)->signData("Hello world", SignFlag::SIGN_CMS | SignFlag::OUT_PEM);
```

### 2. Using only Adapter::class
```php
$adapter = Adapter::getInstance();

$adapter -> loadKeyStore( Adapter::KCST_PKCS12, '/path/to/keyStore.p12', 'password');

// use if CA certs not registered in system
// $adapter->loadCertFromFile(Adapter::KC_CERT_INTERMEDIATE, '/path/to/nca_gost.pem');
// $adapter->loadCertFromFile(Adapter::KC_CERT_CA, '/path/to/root_gost.pem');

return $a->signData( "Hello World", 
    Adapter::KC_SIGN_CMS | 
    Adapter::KC_IN_PEM   | 
    Adapter::KC_OUT_PEM 
);
```

### 3. Use Wsse client

```php
$provider = Provider::init(
    Chain::init(
        KeyStore::load('/path/to/keyStore.p12', 'password')
    )->fromAuthInfo()
);

$client = new WsseClient($provider, [
    "location" => "http://192.168.1.1/bip-sync-wss-gost/",
    "uri" => "http://bip.bee.kz/SyncChannel/v10/Types",
    'proxy_host' => '127.0.0.1',
    'proxy_port' => 80
]);
return $client->SendMessage(new \SoapVar('<mydata>Hello World</mydata>', XSD_ANYXML));
```

