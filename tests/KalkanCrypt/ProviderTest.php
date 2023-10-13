<?php

namespace KalkanCrypt;

use KalkanCrypt\Flags\SignFlag;
use PHPUnit\Framework\TestCase;

class ProviderTest extends TestCase
{
    private string $key_path = __DIR__ . '/../fixtures/gost2015/GOST512_first_director_valid.p12';
    private string $pass = 'Qwerty12';
    private Chain $chain;

    public function setUp(): void
    {
        $kStore = KeyStore::load($this->key_path, $this->pass);
        $this->chain  = Chain::init($kStore)->fromAuthInfo();
    }

    public function testSignData()
    {
        $sign = Provider::init($this->chain)->signData("Hello world", SignFlag::SIGN_CMS | SignFlag::OUT_PEM);
        $this->assertStringStartsWith("-----BEGIN CMS-----", $sign);
    }

    public function testSignXml()
    {
        $xml = '<root><signature></signature><data id="sign-this">Hello World</data></root>';
        $sign = Provider::init($this->chain)->signXML($xml, 'sign-this', 'signature');
        $this->assertStringContainsString("<ds:X509Certificate>", $sign);
    }

    public function testSignWsse()
    {
        $wsse = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                    <Header></Header>
                    <Body id="sign-this">Hello World</Body>
                 </soap:Envelope>';
        $sign = Provider::init($this->chain)->signWSSE($wsse, 'sign-this');
        $this->assertStringContainsString("<ds:SignatureValue>", $sign);
    }
}
