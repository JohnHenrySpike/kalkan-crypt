<?php


namespace certs_registered;

use KalkanCrypt\CertCollection;
use KalkanCrypt\Certificate\Certificate;
use KalkanCrypt\Chain;
use KalkanCrypt\KeyStore;
use PHPUnit\Framework\TestCase;

class ChainTest extends TestCase
{
    private KeyStore $keyStore;

    public function setUp(): void
    {
        $this->keyStore = KeyStore::load(__DIR__ . '/../fixtures/storage/GOST512_first_director_valid.p12', 'Qwerty12');
    }

    public function testFromSystem()
    {
        $this->assertTrue(Chain::init($this->keyStore)->fromSystem()->isReady());
    }
}
