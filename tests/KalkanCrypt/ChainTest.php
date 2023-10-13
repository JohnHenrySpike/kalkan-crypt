<?php


namespace KalkanCrypt;

use KalkanCrypt\Certificate\Certificate;
use PHPUnit\Framework\TestCase;

class ChainTest extends TestCase
{
    private KeyStore $keyStore;

    public function setUp(): void
    {
        $this->keyStore = KeyStore::load(__DIR__ . '/../fixtures/gost2015/GOST512_first_director_valid.p12', 'Qwerty12');
    }

    public function testFromFolder()
    {
        $this->assertTrue(
            Chain::init($this->keyStore)->fromFolder(__DIR__ . '/../fixtures/CaCerts')->isReady()
        );
    }

    public function testFromSystem()
    {
        $this->expectException(\Exception::class);
        $this->assertFalse(Chain::init($this->keyStore)->fromSystem()->isReady());
    }

    public function testFromAuthInfo()
    {
        $this->assertTrue(Chain::init($this->keyStore)->fromAuthInfo()->isReady());
    }

    public function testFromAuthInfoWithCustomLoader()
    {
        $custom_loader = function($url){
            return file_get_contents($url);
        };
        $this->assertTrue(Chain::init($this->keyStore)->fromAuthInfo($custom_loader)->isReady());
    }

    public function testFromCollection()
    {
        $collection = new CertCollection();
        $collection->addItem(Certificate::loadFromPath(__DIR__ . '/../fixtures/CaCerts/nca_gost2022_test.cer'));
        $collection->addItem(Certificate::loadFromPath(__DIR__ . '/../fixtures/CaCerts/root_test_gost_2022.cer'));
        $this->assertTrue(Chain::init($this->keyStore)->fromCollection($collection)->isReady());
    }

    public function testValidate()
    {
        $collection = new CertCollection();
        $collection->addItem(Certificate::loadFromPath(__DIR__ . '/../fixtures/CaCerts/nca_gost2022_test.cer'));
        $collection->addItem(Certificate::loadFromPath(__DIR__ . '/../fixtures/CaCerts/root_test_gost_2022.cer'));
        $chain = Chain::init($this->keyStore)->fromCollection($collection)->validate();

        $this->assertTrue($chain->isValid());
    }

    public function testFromUrl()
    {
        $arUrls = [
            "http://test.pki.gov.kz/cert/nca_gost2022_test.cer",
            "http://root.gov.kz/cert/root_test_gost_2022.cer"
        ];
        $this->assertTrue(Chain::init($this->keyStore)->fromUrl($arUrls)->isReady());
    }
}
