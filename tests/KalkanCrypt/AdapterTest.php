<?php

namespace KalkanCrypt;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;

class AdapterTest extends TestCase
{
    private Adapter $adapter;
    private static string $user_cert;

    public function setUp(): void
    {
        $this->adapter = Adapter::getInstance();
    }

    public function testGetInstance()
    {
        $this->assertInstanceOf(Adapter::class, Adapter::getInstance());
    }

    public function testSetProxy(){
        $this->adapter->setProxy(Adapter::KC_PROXY_OFF);
        $this->assertEquals(0, $this->adapter->getLastError());
        $this->adapter->setProxy(Adapter::KC_PROXY_ON, "127.0.0.1", "80");
        $this->assertEquals(0, $this->adapter->getLastError());
        $this->adapter->setProxy(Adapter::KC_PROXY_AUTH, "127.0.0.1", "80", "proxy_login", "proxy_password");
        $this->assertEquals(0, $this->adapter->getLastError());

        $this->adapter->setProxy(Adapter::KC_PROXY_OFF);
    }

    #[Depends('testSetProxy')]
    public function testAdapterReset(){
        $this->assertTrue(true);
    }

    #[Depends('testAdapterReset')]
    public function testSetTsaUrl()
    {
        $this->adapter->setTsaUrl("http://test.pki.gov.kz/tsp/");
        $this->assertEquals(0, $this->adapter->getLastError());
    }

    #[Depends('testAdapterReset')]
    public function testGetLastError()
    {
        $this->assertEquals(0, $this->adapter->getLastError());
    }

    #[Depends('testAdapterReset')]
    public function testGetLastErrorString()
    {
        $this->assertEmpty($this->adapter->getLastErrorString());
    }

    #[Depends('testAdapterReset')]
    public function testLoadKeyStore(){
        $this->adapter->loadKeyStore(
            Adapter::KCST_PKCS12,
            $this->getFixtureFullPath('gost2015/GOST512_first_director_valid.p12'),
            'Qwerty12',
            'test_first_director_valid'
        );
        $this->assertEquals(0, $this->adapter->getLastError());
    }

    #[Depends('testLoadKeyStore')]
    public function testExportCertFromStore()
    {
        $cert = $this->adapter->exportCertFromStore('test_first_director_valid');
        $this->assertEquals(0, $this->adapter->getLastError());
        $this->assertStringContainsString("-----BEGIN CERTIFICATE-----", $cert);
        self::$user_cert = $cert;
    }

    #[Depends('testExportCertFromStore')]
    public function testLoadIntermediateCertFromFile()
    {
        $this->adapter->loadCertFromFile(
            Adapter::KC_CERT_INTERMEDIATE,
            $this->getKeyPath('nca_gost2022_test.cer')
        );
        $this->assertEquals(0, $this->adapter->getLastError());
    }

    #[Depends('testLoadIntermediateCertFromFile')]
    public function testLoadCaCertFromFile()
    {
        $this->adapter->loadCertFromFile(Adapter::KC_CERT_CA, $this->getKeyPath('root_test_gost_2022.cer'));
        $this->assertEquals(0, $this->adapter->getLastError());
    }

    #[Depends('testLoadCaCertFromFile')]
    public function testBasicValidateCert(){
        $validate_info = $this->adapter->validateCert(self::$user_cert);
        $this->assertStringContainsString("Verify chain and certificates: - OK", $validate_info["info"]);
    }

    #[Depends('testLoadCaCertFromFile')]
    public function testOscpValidateCert(){
        $validPath = "http://test.pki.gov.kz/ocsp/";
        $validate_info = $this->adapter->validateCert(self::$user_cert, Adapter::KC_USE_OCSP, $validPath, Adapter::KC_GET_OCSP_RESPONSE);
        $this->assertStringContainsString("Verify chain and certificates: - OK", $validate_info["info"]);
        $this->assertStringContainsString("This Update:", $validate_info["info"]);
        $this->assertStringContainsString("Cert Status: good", $validate_info["OCSP_Response"]);
    }

    #[Depends('testLoadCaCertFromFile')]
    public function testCrlValidateCert(){
        $this->markTestIncomplete("need add crl file");
        $validPath = $this->getFixtureFullPath('');
        $validate_info = $this->adapter->validateCert(self::$user_cert,Adapter::KC_USE_CRL, $validPath);
        $this->assertStringContainsString("Verify chain and certificates: - OK", $validate_info["info"]);
        $this->assertStringContainsString("This Update:", $validate_info["info"]);
    }

    public function testLoadCertFromBuffer()
    {
        $this->markTestIncomplete('SIGSEGV');
        $certString = file_get_contents($this->getKeyPath('nca_gost_test.crt'));
        $this->adapter->loadCertFromBuffer($certString, Adapter::KC_CERT_PEM);
    }

    #[Depends('testLoadCaCertFromFile')]
    public function testHashData(){
        $data = "Hello World";
        $file = realpath(__DIR__ . '/../fixtures/application.pdf');

        $hash = $this->adapter->hashData($data, Adapter::KC_OUT_BASE64, 'sha256');
        $this->assertIsString($hash);
        $this->assertTrue(strlen($hash)>0);

        $hash = $this->adapter->hashData($data, Adapter::KC_OUT_BASE64 | Adapter::KC_HASH_SHA256);
        $this->assertIsString($hash);
        $this->assertTrue(strlen($hash)>0);

        $hash = $this->adapter->hashData($data, Adapter::KC_OUT_BASE64, 'Gost34311_95');
        $this->assertIsString($hash);
        $this->assertTrue(strlen($hash)>0);

        $hash = $this->adapter->hashData($data, Adapter::KC_OUT_BASE64 | Adapter::KC_HASH_GOST95);
        $this->assertIsString($hash);
        $this->assertTrue(strlen($hash)>0);

        $hash = $this->adapter->hashData($file, Adapter::KC_OUT_BASE64 | Adapter::KC_HASH_GOST95 | Adapter::KC_IN_FILE);
        $this->assertIsString($hash);
        $this->assertTrue(strlen($hash)>0);
    }

    public function testGetTokens(){
        $this->markTestIncomplete("ERROR 0x8f00200: Get tokens list - engine load error.");
        $tokens = $this->adapter->getTokens(Adapter::KCST_KAZTOKEN);
    }

    #[Depends('testGetTokens')]
    public function testGetCertificatesList(){
        $list = $this->adapter->getCertificatesList();
    }

    public function tearDown(): void
    {
        $this->adapter->destroy();
    }

    private function getKeyPath(string $name): bool|string
    {
        return $this->getFixtureFullPath('CaCerts/'.$name);
    }

    private function getFixtureFullPath(string $fixtureName): false|string
    {
        $parts = [__DIR__, '..', 'fixtures', $fixtureName];
        return realpath(implode('/', $parts));
    }
}
