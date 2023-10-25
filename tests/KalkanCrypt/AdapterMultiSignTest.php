<?php

namespace KalkanCrypt;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;

class AdapterMultiSignTest extends TestCase
{
    private Adapter $adapter;

    private string $unsigned_data = "Hello World";

    public static function setUpBeforeClass(): void
    {
        date_default_timezone_set('Asia/Almaty');
    }

    public function testCmsSignPemDetachedDataCmsSignatureInPem(){
        $this->adapter = Adapter::getInstance();
        $this->adapter->loadKeyStore(
            Adapter::KCST_PKCS12,
            self::getFixturePath('gost2015/GOST512_first_director_valid.p12'),
            'Qwerty12',
            'test_first_director_valid'
        );
        $this->adapter->loadCertFromFile(Adapter::KC_CERT_CA, self::getFixturePath('CaCerts/root_test_gost_2022.cer'));
        $this->adapter->loadCertFromFile(Adapter::KC_CERT_INTERMEDIATE, self::getFixturePath('/CaCerts/nca_gost2022_test.cer'));

        $signed_data = $this->adapter->signData(
            $this->unsigned_data,
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_PEM | Adapter::KC_OUT_PEM | Adapter::KC_DETACHED_DATA
        );
        $this->adapter->destroy();
        $this->assertTrue(strlen($signed_data) > 0, "SignData returned empty string");
        return $signed_data;
    }

    /**
     * Мультиподпись в формате PEM
     */
    #[Depends('testCmsSignPemDetachedDataCmsSignatureInPem')]
    public function testMultiCmsSignPemDetachedDataCmsSignatureInPem(string $signed_data){
        $this->adapter = Adapter::getInstance();
        $this->adapter->loadKeyStore(
            Adapter::KCST_PKCS12,
            self::getFixturePath('gost2015/GOST512_employee_with_signatory_authority_valid.p12'),
            'Qwerty12',
            'employee_with_signature'
        );
        $this->adapter->loadCertFromFile(Adapter::KC_CERT_CA, self::getFixturePath('CaCerts/root_test_gost_2022.cer'));
        $this->adapter->loadCertFromFile(Adapter::KC_CERT_INTERMEDIATE, self::getFixturePath('/CaCerts/nca_gost2022_test.cer'));

        $multi_signed_data = $this->adapter->signData(
            $this->unsigned_data,
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_PEM | Adapter::KC_OUT_PEM | Adapter::KC_DETACHED_DATA,
            $signed_data
        );
        $this->assertNotEmpty($multi_signed_data);
        $this->assertTrue(strlen($multi_signed_data) > 0, "SignData returned empty string");
        return $multi_signed_data;
    }

    #[Depends('testMultiCmsSignPemDetachedDataCmsSignatureInPem')]
    public function testVerifyMultiCmsSignPemDetachedDataCmsSignatureInPem(string $signed_data){
        $this->adapter = Adapter::getInstance();
        $verify_res = $this->adapter->verifyData(
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_PEM | Adapter::KC_OUT_PEM | Adapter::KC_DETACHED_DATA,
            $this->unsigned_data,
            $signed_data
        );
        $this->adapter->destroy();
        $this->assertIsArray($verify_res);
        $this->assertStringContainsString("Signature N 1", $verify_res['info']);
        $this->assertStringContainsString("Signature N 2", $verify_res['info']);
        $this->assertStringContainsString("verify signer certificate hash - OK", $verify_res['info']);
        $this->assertStringContainsString("Verify - OK", $verify_res['info']);
        $this->assertStringContainsString("CMS Verify - OK", $verify_res['info']);
    }


    /** Helper method
     *
     * @param string $fixtureName
     * @return false|string
     */
    private static function getFixturePath(string $fixtureName = ""): false|string
    {
        $parts = [__DIR__, '..', 'fixtures', $fixtureName];
        return realpath(implode('/', $parts));
    }
}