<?php
namespace KalkanCrypt;
use Exception;
use KalkanCrypt\Certificate\Certificate;

class CertManager{

    /**
     * @return CertCollection
     * @throws Exception
     */
    public static function loadFromSystem(): CertCollection
    {
        $certs = new CertCollection();
        $sys_store = openssl_get_cert_locations()['default_cert_dir'];
        foreach (scandir($sys_store) as $value){
            if (strpos($value, '.pem')) {
                $cert = Certificate::loadFromPath($sys_store . "/" . $value);
                $certs->addItem($cert, $cert->getSubjectKeyIdentifier());
            }
        }
        return $certs;
    }

    /**
     * @param Certificate $cert
     * @param CertCollection $collection
     * @param bool $load try to load next cert in chain from AuthorityInfoAccess
     * @return CertCollection
     * @throws Exception
     */
    public static function createChain(Certificate $cert, CertCollection $collection = new CertCollection(), bool $load = false): CertCollection
    {
        $chain_collection = new CertCollection();
        while($cert = self::findCertByAuthorityKeyIdentifier($cert, $collection, $load)){
            $chain_collection->addItem($cert);
            if ($cert->isRootCert()) break;
        }
        return $chain_collection;
    }

    /**
     * @throws Exception
     */
    private static function findCertByAuthorityKeyIdentifier(Certificate $needle, CertCollection $collection, bool $load = false): bool|Certificate
    {
        foreach ($collection->all() as $cert) {
            if ($cert->getSubjectKeyIdentifier() == $needle->getAuthorityKeyIdentifier()) {
                return $cert;
            }
        }
        if ($load){
            $cer_cert = file_get_contents($needle->getAuthorityUrl());
            if ($cer_cert === false){
                throw new Exception(
                    "Can't load Certificate for AuthorityKeyIdentifier [".$needle->getAuthorityKeyIdentifier()
                    ."]\n"
                    .$needle->getAuthorityInfoAccess()."\n".implode("\n", $needle->getIssuer())
                );
            }
            return static::certLoad($needle);
        }

        throw new Exception(
            "Not found Certificate for AuthorityKeyIdentifier [".$needle->getAuthorityKeyIdentifier()
            ."]\n"
            .$needle->getAuthorityInfoAccess()
        );
    }

    /**
     * @throws Exception
     */
    protected static function certLoad(Certificate $needle): Certificate
    {
        $loaded_cert = file_get_contents($needle->getAuthorityUrl());
        if ($loaded_cert === false){
            throw new Exception(
                "Can't load Certificate for AuthorityKeyIdentifier [".$needle->getAuthorityKeyIdentifier()
                ."]\n"
                .$needle->getAuthorityInfoAccess()."\n".implode("\n", $needle->getIssuer())
            );
        }
        return Certificate::loadFromString($loaded_cert);
    }
}