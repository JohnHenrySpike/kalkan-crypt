<?php

namespace KalkanCrypt;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;
use PHPUnit\Util\Reflection;

class AdapterCertInfoTest extends TestCase
{
    private static string $cert;
    private static Adapter $adapter;

    public static function setUpBeforeClass(): void
    {
        self::$adapter = Adapter::getInstance();
        self::$adapter->loadKeyStore(
            Adapter::KCST_PKCS12,
            __DIR__ . '/../fixtures/gost2015/GOST512_first_director_valid.p12',
            'Qwerty12',
            'test_first_director_valid'
        );
        self::$cert = self::$adapter->exportCertFromStore('test_first_director_valid');
    }

    public function testGetCertInfoIssuerCountryname(){
        $this->assertStringContainsString("C=", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_ISSUER_COUNTRYNAME, self::$cert));
    }

    public function testGetCertInfoIssuerSopn(){
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_ISSUER_SOPN, self::$cert));
    }

    public function testGetCertInfoIssuerLocalityName(){
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_ISSUER_LOCALITYNAME, self::$cert));
    }

    public function testGetCertInfoIssuerOrgName(){
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_ISSUER_ORG_NAME, self::$cert));
    }

    public function testGetCertInfoIssuerOrgunitName(){
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_ISSUER_ORGUNIT_NAME, self::$cert));
    }

    public function testGetCertInfoIssuerCommonName(){
        $this->assertStringContainsString("CN=", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_ISSUER_COMMONNAME, self::$cert));
    }

    public function testGetCertInfoSubjectCountryname(){
        $this->assertStringContainsString("C=KZ", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_COUNTRYNAME, self::$cert));
    }

    public function testGetCertInfoSubjectSopn(){
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_SOPN, self::$cert));
    }
    public function testGetCertInfoSubjectLocalityName(){
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_LOCALITYNAME, self::$cert));
    }
    public function testGetCertInfoSubjectCommonName(){
        $this->assertStringContainsString("CN=ТЕСТОВ ТЕСТ", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_COMMONNAME, self::$cert));
    }
    public function testGetCertInfoSubjectGivenName(){
        $this->assertStringContainsString("GN=ТЕСТОВИЧ", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_GIVENNAME, self::$cert));
    }
    public function testGetCertInfoSubjectSurname(){
        $this->assertStringContainsString("SN=ТЕСТОВ", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_SURNAME, self::$cert));
    }
    public function testGetCertInfoSubjectSerialNumber(){
        $this->assertStringContainsString("serialNumber=IIN123456789011", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_SERIALNUMBER, self::$cert));
    }
    public function testGetCertInfoSubjectEmail(){
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_EMAIL, self::$cert));
    }
    public function testGetCertInfoSubjectOrgName(){
        $this->assertStringContainsString("O=АО \"ТЕСТ\"", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_ORG_NAME, self::$cert));
    }
    public function testGetCertInfoSubjectOrgUnitName(){
        $this->assertStringContainsString("OU=BIN123456789021", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_ORGUNIT_NAME, self::$cert));
    }
    public function testGetCertInfoSubjectBc(){
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_BC, self::$cert));
    }
    public function testGetCertInfoSubjectDc(){
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_DC, self::$cert));
    }
    public function testGetCertInfoNotBefore(){
        $this->assertStringContainsString("notBefore=", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_NOTBEFORE, self::$cert));
    }
    public function testGetCertInfoNotAfter(){
        $this->assertStringContainsString("notAfter=", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_NOTAFTER, self::$cert));
    }
    public function testGetCertInfoKeyUsage(){
        $this->assertStringContainsString("keyUsage=digitalSignature nonRepudiation keyAgreement", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_KEY_USAGE, self::$cert));
    }
    public function testGetCertInfoExtKeyUsage(){
        $this->assertStringContainsString("extendedKeyUsage=", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_EXT_KEY_USAGE, self::$cert));
    }
    public function testGetCertInfoAuthKeyId(){
        $this->assertStringContainsString("authorityKeyIdentifier=", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_AUTH_KEY_ID, self::$cert));
    }
    public function testGetCertInfoSubjectKeyId(){
        $this->assertStringContainsString("subjectKeyIdentifier=", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJ_KEY_ID, self::$cert));
    }
    public function testGetCertInfoCertSn(){
        $this->assertStringContainsString("certificateSerialNumber=", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_CERT_SN, self::$cert));
    }
    public function testGetCertInfoIssuerDn(){
        $this->assertStringContainsString("CN", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_ISSUER_DN, self::$cert));
    }
    public function testGetCertInfoSubjectDn(){
        $this->assertStringContainsString("CN", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SUBJECT_DN, self::$cert));
    }
    public function testGetCertInfoSignatureAlg(){
        $this->assertStringContainsString("signatureAlgorithm=", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_SIGNATURE_ALG, self::$cert));
    }
    public function testGetCertInfoPubKey(){
        $this->assertTrue((bool)strlen(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_PUBKEY, self::$cert)));
    }
    public function testGetCertInfoPoliciesId(){
        $this->assertStringContainsString("certificatePolicies=", self::$adapter->getCertInfo(Adapter::KC_CERTPROP_POLICIES_ID, self::$cert));
    }

    public function testGetCertInfoOcsp(){
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_OCSP, self::$cert));
    }
    public function testGetCertInfoGetCrl(){
        $this->markTestIncomplete("SIGSEGV");
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_GET_CRL, self::$cert));
    }
    public function testGetCertInfoDeltaCrl(){
        $this->markTestIncomplete("SIGSEGV");
        $this->assertIsString(self::$adapter->getCertInfo(Adapter::KC_CERTPROP_GET_DELTA_CRL, self::$cert));
    }
}
