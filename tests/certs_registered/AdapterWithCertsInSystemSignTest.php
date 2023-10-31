<?php

namespace certs_registered;

use KalkanCrypt\Adapter;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\DependsExternal;
use PHPUnit\Framework\TestCase;

class AdapterWithCertsInSystemSignTest extends TestCase
{
    private Adapter $adapter;

    private string $unsigned_data = "Hello World";

    public static function setUpBeforeClass(): void
    {
        date_default_timezone_set('Asia/Almaty');
    }

    public function setUp(): void
    {
        $this->adapter = Adapter::getInstance();
        $this->adapter->setTsaUrl('http://test.pki.gov.kz/tsp/');
        $this->adapter->loadKeyStore(
            Adapter::KCST_PKCS12,
            __DIR__.'/../fixtures/storage/GOST512_first_director_valid.p12',
            'Qwerty12',
            'test_first_director_valid'
        );
    }

    /**
     * CMS-подпись в формате PEM. Без метки времени(Данные - просто текст)
     */
    public function testSignStringDataCmsSignatureInPemWithoutTimestamp(){
        $signed_data = $this->adapter->signData(
            $this->unsigned_data,
            Adapter::KC_SIGN_CMS | Adapter::KC_OUT_PEM
        );
        $this->assertIsString($signed_data);
        return $signed_data;
    }

    #[Depends('testSignStringDataCmsSignatureInPemWithoutTimestamp')]
    public function testVerifySignedStringDataCmsSignatureInPemWithoutTimestamp(string $signed_data){
        $verify_res = $this->adapter->verifyData(
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_PEM | Adapter::KC_OUT_PEM,
            $this->unsigned_data,
            $signed_data
        );
        $this->assertIsArray($verify_res);
        $this->assertArrayHasKey('info', $verify_res);
        $this->assertStringContainsString("verify signer certificate hash - OK", $verify_res['info']);
        $this->assertStringContainsString("Verify - OK", $verify_res['info']);
        $this->assertStringContainsString("CMS Verify - OK", $verify_res['info']);
        return $signed_data;
    }

    #[Depends('testVerifySignedStringDataCmsSignatureInPemWithoutTimestamp')]
    public function testGetCertFromCms(string $cms_signed_data){
        $cert = $this->adapter->getCertFromCMS($cms_signed_data,1, Adapter::KC_SIGN_CMS | Adapter::KC_IN_PEM | Adapter::KC_OUT_PEM);
        $this->assertIsString($cert);
        $this->assertTrue(strlen($cert)>0);
        $this->assertStringContainsString("-----BEGIN CERTIFICATE-----", $cert);
    }


    public function tearDown(): void
    {
        $this->adapter->destroy();
    }
}