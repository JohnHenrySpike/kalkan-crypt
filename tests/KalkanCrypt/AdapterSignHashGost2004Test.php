<?php

namespace KalkanCrypt;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\DependsExternal;
use PHPUnit\Framework\TestCase;

class AdapterSignHashGost2004Test extends TestCase
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
            __DIR__. '/../fixtures/storage/GOSTKNCA_first_director_valid.p12',
            'Qwerty12',
            'test_first_director_valid'
        );
        $this->adapter->loadCertFromFile(
            Adapter::KC_CERT_CA,
            __DIR__ . '/../fixtures/ca-certs/root_test_gost_2022.cer');

        $this->adapter->loadCertFromFile(
            Adapter::KC_CERT_INTERMEDIATE,
            __DIR__ . '/../fixtures/ca-certs/nca_gost2022_test.cer');
    }

    /**
     * @return void
     * @throws Exception\AdapterException
     */
    public function testSignHash(){
        $hashed_data = $this->adapter->hashData(
            $this->unsigned_data,
            Adapter::KC_OUT_BASE64 | Adapter::KC_HASH_GOST95);

        $signed_hash = $this->adapter->signHash(
            $hashed_data,
            Adapter::KC_SIGN_CMS | Adapter::KC_IN_BASE64 | Adapter::KC_OUT_PEM, "sha256"
        );
        $this->assertIsString($signed_hash);
        $this->assertTrue(strlen($signed_hash) > 0);
    }

    public function tearDown(): void
    {
        $this->adapter->destroy();
    }
}