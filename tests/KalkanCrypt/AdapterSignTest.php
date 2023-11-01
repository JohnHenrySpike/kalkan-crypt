<?php

namespace KalkanCrypt;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\DependsExternal;
use PHPUnit\Framework\TestCase;

class AdapterSignTest extends TestCase
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
            self::getFixturePath('storage/GOST512_first_director_valid.p12'),
            'Qwerty12',
            'test_first_director_valid'
        );
        $this->adapter->loadCertFromFile(Adapter::KC_CERT_CA, self::getFixturePath('ca-certs/root_test_gost_2022.cer'));
        $this->adapter->loadCertFromFile(Adapter::KC_CERT_INTERMEDIATE, self::getFixturePath('/ca-certs/nca_gost2022_test.cer'));
    }

    public function testSignZipCon(){
        $save_path = self::getFixturePath();

        $one_file = self::getFixturePath('unsigned.txt').'|';
        $many_files = self::getFixturePath('unsigned.txt'). '|' . self::getFixturePath('application.pdf') . '|';
        $this->adapter->signZipCon($one_file, 'arch', $save_path);
        $this->adapter->signZipCon($many_files, 'arch_many', $save_path);
        $this->assertEquals(0, $this->adapter->getLastError());

        /*
         * remove 3 lines below when error fixed
        */
        $this->assertTrue(unlink($save_path.'/arch.zip'), "File (".$save_path.'/arch.zip'.") delete failed");
        $this->assertTrue(unlink($save_path.'/arch_many.zip'), "File (".$save_path.'/arch_many.zip'.") delete failed");
        $this->markTestIncomplete('ERROR (files in arch is empty) [confirmed] https://forum.pki.gov.kz/t/php-kalkancrypt-zipconsign-sozdaet-arhiv-s-pustymi-fajlami/2485/4');

        return $save_path;
    }

    #[Depends('testSignZipCon')]
    public function testVerifyZipCon(){
        $save_path = self::getFixturePath();
        $this->assertTrue(unlink($save_path.'/arch.zip'), "File (".$save_path.'/arch.zip'.") delete failed");
        $this->assertTrue(unlink($save_path.'/arch_many.zip'), "File (".$save_path.'/arch_many.zip'.") delete failed");
      
        $verify = $this->adapter->verifyZipCon($save_path.'/arch.zip');
        $verify = $this->adapter->verifyZipCon($save_path.'/arch_many.zip');
    }

    #[Depends('testVerifyZipCon')]
    public function testGetCertFromZipFile(string $path){
        $cert = $this->adapter->getCertFromZip($path . '/arch.zip');
        $this->assertTrue(strlen($cert) > 0);
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

    /**
     * CMS-подпись в формате PEM. С меткой времени
     */
    public function testSignStringDataCmsSignatureInPemWithTimestamp(){
        $this->adapter->setTsaUrl('http://test.pki.gov.kz/tsp/');
        $signed_data = $this->adapter->signData(
            $this->unsigned_data,
            Adapter::KC_SIGN_CMS | Adapter::KC_OUT_PEM | Adapter::KC_WITH_TIMESTAMP
        );
        $this->assertIsString($signed_data);
        return $signed_data;
    }

    #[Depends('testSignStringDataCmsSignatureInPemWithTimestamp')]
    public function testVerifySignedStringDataCmsSignatureInPemWithTimestamp($signed_data){
        $verify_res = $this->adapter->verifyData(
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_PEM | Adapter::KC_OUT_PEM | Adapter::KC_WITH_TIMESTAMP,
            $this->unsigned_data,
            $signed_data
        );
        $this->assertIsArray($verify_res);
        $this->assertArrayHasKey('info', $verify_res);
        $this->assertStringContainsString("verify signer certificate hash - OK", $verify_res['info']);
        $this->assertStringContainsString("Signing time ".date("d.m.Y"), $verify_res['info']);
        $this->assertStringContainsString("Verify - OK", $verify_res['info']);
        $this->assertStringContainsString("CMS Verify - OK", $verify_res['info']);
        return $signed_data;
    }

    #[Depends('testVerifySignedStringDataCmsSignatureInPemWithTimestamp')]
    public function testGetTimeFromSignedData(string $cms_signed_data){
        $time = $this->adapter->getTimeFromSig($cms_signed_data, Adapter::KC_SIGN_CMS | Adapter::KC_IN_PEM | Adapter::KC_OUT_PEM | Adapter::KC_WITH_TIMESTAMP);
        $this->assertIsInt($time);
    }

    /**
     * Сырая подпись данных (DraftSign) в BASE64(Данные - просто текст)
     */
    public function testSignStringDataDraftSignatureInBase64(){
        $signed_data = $this->adapter->signData(
            $this->unsigned_data,
            Adapter::KC_SIGN_DRAFT | Adapter::KC_OUT_BASE64
        );
        $this->assertIsString($signed_data);
        return $signed_data;
    }

    #[Depends('testSignStringDataDraftSignatureInBase64')]
    public function testVerifySignedStringDataDraftSignatureInBase64(string $signed_data){
        $verify_res = $this->adapter->verifyData(
            Adapter::KC_SIGN_DRAFT | Adapter::KC_IN_BASE64 | Adapter::KC_IN_PEM,
            $this->unsigned_data,
            $signed_data
        );
        $this->assertIsArray($verify_res);
        $this->assertStringContainsString("Verify - OK", $verify_res['info']);
    }

    /**
     * Сырая подпись данных (DraftSign) в BASE64(Данные в BASE64)
     */
    public function testSignBase64DataDraftSignatureInBase64(){
        $signed_data = $this->adapter->signData(
            base64_encode($this->unsigned_data),
            Adapter::KC_SIGN_DRAFT | Adapter::KC_IN_BASE64 | Adapter::KC_OUT_BASE64
        );
        $this->assertIsString($signed_data);
        return $signed_data;
    }

    #[Depends('testSignBase64DataDraftSignatureInBase64')]
    public function testVerifySignedBase64DataDraftSignatureInBase64(string $signed_data){
        $verify_res = $this->adapter->verifyData(
            Adapter::KC_SIGN_DRAFT | Adapter::KC_IN_BASE64 | Adapter::KC_IN2_BASE64,
            base64_encode($this->unsigned_data),
            $signed_data
        );
        $this->assertIsArray($verify_res);
        $this->assertStringContainsString("Verify - OK", $verify_res['info']);
    }

    /**
     * CMS-detached в формате PEM(Данные-текст. хранятся отдельно)
     */
    public function testSignStringDetachedDataCmsSignatureInPem(){
        $signed_data = $this->adapter->signData(
            $this->unsigned_data,
            Adapter::KC_SIGN_CMS | Adapter::KC_OUT_PEM | Adapter::KC_DETACHED_DATA
        );
        $this->assertIsString($signed_data);
        return $signed_data;
    }

    #[Depends('testSignStringDetachedDataCmsSignatureInPem')]
    public function testVerifySignedStringDetachedDataCmsSignatureInPem(string $signed_data){
        $verify_res = $this->adapter->verifyData(
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_PEM | Adapter::KC_OUT_PEM | Adapter::KC_DETACHED_DATA,
            $this->unsigned_data,
            $signed_data
        );
        $this->assertIsArray($verify_res);
        $this->assertStringContainsString("verify signer certificate hash - OK", $verify_res['info']);
        $this->assertStringContainsString("Verify - OK", $verify_res['info']);
        $this->assertStringContainsString("CMS Verify - OK", $verify_res['info']);
    }

    /**
     * CMS-detached в формате BASE64(Данные-BASE64 хранятся отдельно)
     */
    public function testSignBase64DetachedDataCmsSignatureInBase64(){
        $signed_data = $this->adapter->signData(
            base64_encode($this->unsigned_data),
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_BASE64 | Adapter::KC_OUT_BASE64 | Adapter::KC_DETACHED_DATA
        );
        $this->assertIsString($signed_data);
        return $signed_data;
    }

    #[Depends('testSignBase64DetachedDataCmsSignatureInBase64')]
    public function testVerifySignBase64DetachedDataCmsSignatureInBase64(string $signed_data){
        $verify_res = $this->adapter->verifyData(
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_BASE64 | Adapter::KC_IN2_BASE64 | Adapter::KC_OUT_BASE64 | Adapter::KC_DETACHED_DATA,
            base64_encode($this->unsigned_data),
            $signed_data
        );
        $this->assertIsArray($verify_res);
        $this->assertStringContainsString("verify signer certificate hash - OK", $verify_res['info']);
        $this->assertStringContainsString("Verify - OK", $verify_res['info']);
        $this->assertStringContainsString("CMS Verify - OK", $verify_res['info']);
    }

    /**
     * Подписать pdf-файлa в формате BASE64
     */
    public function testSignPdfFileCmsSignatureInBase64(){
        $data = self::getFixturePath('application.pdf');
        $signed_data = $this->adapter->signData(
            $data,
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_FILE | Adapter::KC_OUT_BASE64
        );
        $this->assertIsString($signed_data);
        $signed_file_path = __DIR__ . '/../fixtures/signed.pdf';
        fwrite(fopen($signed_file_path, "w"), $signed_data);
        return $signed_file_path;
    }

    #[Depends('testSignPdfFileCmsSignatureInBase64')]
    public function testVerifySignPdfFileCmsSignatureInBase64(string $signed_file_path){
        $data = self::getFixturePath('application.pdf');
        $verify_res = $this->adapter->verifyData(
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_BASE64 | Adapter::KC_IN_FILE | Adapter::KC_OUT_BASE64 | Adapter::KC_NOCHECKCERTTIME,
            $data,
            $signed_file_path
        );
        $this->assertIsArray($verify_res);
        $this->assertStringContainsString("Signature N 1", $verify_res['info']);
        $this->assertStringContainsString("verify signer certificate hash - OK", $verify_res['info']);
        $this->assertStringContainsString("Verify - OK", $verify_res['info']);
        $this->assertStringContainsString("CMS Verify - OK", $verify_res['info']);
        $this->assertTrue(unlink($signed_file_path), "File (".$signed_file_path.")delete failed");
    }


    public function testSignHashGost2015(){
        $hashed_data = $this->adapter->hashData(
            $this->unsigned_data,
            Adapter::KC_OUT_BASE64 | Adapter::KC_HASH_GOST2015);

        $signed_hash = $this->adapter->signHash(
            $hashed_data,
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_BASE64 | Adapter::KC_OUT_PEM | Adapter::KC_HASH_GOST2015
        );
        $this->assertIsString($signed_hash);
        $this->assertTrue(strlen($signed_hash) > 0);
    }

    public function testSignXml(){
        $unsigned_xml = file_get_contents(self::getFixturePath('unsigned.xml'));
        $signNodeId = "sign-this-data";
        $signPlaceTagName = "sign_place";
        $signed_xml = $this->adapter->signXML(
            $unsigned_xml,
            $signNodeId,
            $signPlaceTagName,
            ""
        );
        $this->assertIsString($signed_xml);
        return $signed_xml;
    }

    #[Depends('testSignXml')]
    public function testVerifySignedXml(string $signed_xml){
        $verify_res = $this->adapter->verifyXML($signed_xml, 0);
        $this->assertStringContainsString("Signature is OK", $verify_res);
        return $signed_xml;
    }

    #[Depends('testVerifySignedXml')]
    public function testGetCertFromXml(string $signed_xml){
        $cert = $this->adapter->getCertFromXML($signed_xml);
        $this->assertIsString($cert);
        $this->assertTrue(strlen($cert)>0);
        return $signed_xml;
    }

    #[Depends('testGetCertFromXml')]
    public function testGetSigAlgFromXml(string $signed_xml){
        $alg = $this->adapter->getSigAlgFromXML($signed_xml);
        $this->assertIsString($alg);
        $this->assertStringContainsString('signatureAlgorithm=', $alg);
    }

    public function testSignWsse(){
        $signNodeId = "sign-this-data";
        $unsigned_wsse = file_get_contents(self::getFixturePath('unsigned_wsse.xml'));
        $signed_wsse = $this->adapter->signWSSE($unsigned_wsse, $signNodeId);
        $this->assertEquals(0, $this->adapter->getLastError());
        return $signed_wsse;
    }

    #[Depends('testSignWsse')]
    public function testVerifySignedWsse(string $signed_wsse){
        $verify_res = $this->adapter->verifyXML($signed_wsse, 0);
        $this->assertStringContainsString("Signature is OK", $verify_res);
    }


    public function tearDown(): void
    {
        $this->adapter->destroy();
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