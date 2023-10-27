<?php

namespace performance;

use KalkanCrypt\Chain;
use KalkanCrypt\Flags\SignFlag;
use KalkanCrypt\KeyStore;
use KalkanCrypt\Provider;
use PHPUnit\Framework\TestCase;

class ProviderPerformanceTest extends TestCase
{
    private string $key_path = __DIR__ . '/../fixtures/storage/GOST512_first_director_valid.p12';
    private string $pass = 'Qwerty12';
    private Chain $chain;

    public function setUp(): void
    {
        $kStore = KeyStore::load($this->key_path, $this->pass);
        $this->chain  = Chain::init($kStore)->fromAuthInfo();
    }

    public function testSign1000Data()
    {
        $signs = 1000;
        $provider = Provider::init($this->chain);
        $start_at = microtime(true);
        for ($i=0 ; $i<$signs ; $i++) {
            $provider->signData("Hello world", SignFlag::SIGN_CMS | SignFlag::OUT_PEM);
        }
        $stop_at = microtime(true);
        $eta = $stop_at - $start_at;
        fwrite(STDERR,
            "\n$signs data signs (without TSP) in "
            .round($eta, 3)
            ." seconds  ["
            .round($signs/$eta, 1)
            ." signs/sec]\n");
        $this->assertLessThan(5, $eta);
    }

    public function testSignDataWithTimeStamp()
    {
        $signs = 10;
        $provider = Provider::init($this->chain, "http://test.pki.gov.kz/tsp/");
        $start_at = microtime(true);
        for ($i=0 ; $i<$signs ; $i++) {
            $provider->signData("Hello world", SignFlag::SIGN_CMS | SignFlag::OUT_PEM | SignFlag::WITH_TIMESTAMP);
        }
        $stop_at = microtime(true);
        $eta = $stop_at - $start_at;
        fwrite(STDERR,
            "\n$signs data signs (withTSP) in "
            .round($eta, 3)
            ." seconds  ["
            .round($signs/$eta, 1)
            ." signs/sec]\n");
        $this->assertLessThan(20, $eta);
    }

    public function testSignXml()
    {
        $xml = '<root><signature></signature><data id="sign-this">Hello World</data></root>';

        $signs = 1000;
        $provider = Provider::init($this->chain, "http://test.pki.gov.kz/tsp/");
        $start_at = microtime(true);
        for ($i=0 ; $i<$signs ; $i++) {
            $provider->signXML($xml, 'sign-this', 'signature');
        }
        $stop_at = microtime(true);
        $eta = $stop_at - $start_at;
        fwrite(STDERR,
            "\n$signs xml signs (without TSP) in "
            .round($eta, 3)
            ." seconds  ["
            .round($signs/$eta, 1)
            ." signs/sec]\n");
        $this->assertLessThan(20, $eta);
    }

    public function testSignWsse()
    {
        $wsse = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                    <Header></Header>
                    <Body id="sign-this">Hello World</Body>
                 </soap:Envelope>';

        $signs = 1000;
        $provider = Provider::init($this->chain, "http://test.pki.gov.kz/tsp/");
        $start_at = microtime(true);
        for ($i=0 ; $i<$signs ; $i++) {
            $provider->signWSSE($wsse, 'sign-this');
        }
        $stop_at = microtime(true);
        $eta = $stop_at - $start_at;
        fwrite(STDERR,
            "\n$signs wsse signs (without TSP) in "
            .round($eta, 3)
            ." seconds  ["
            .round($signs/$eta, 1)
            ." signs/sec]\n");
        $this->assertLessThan(20, $eta);
    }
}
