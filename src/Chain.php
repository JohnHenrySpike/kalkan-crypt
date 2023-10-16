<?php
namespace KalkanCrypt;
use Closure;
use Exception;
use KalkanCrypt\Certificate\Certificate;

class Chain {

    private KeyStore $keyStore;

    private CertCollection $links;

    private bool $isReady = false;
    private bool $isValid = false;

    private Closure $certLoader;

    private function __construct(){}
    /**
     * Initializer
     *
     * For create chain use methods prefix"from" like:
     *
     * Chain::init($keyStore)->fromSystem()<br/>
     * Chain::init($keyStore)->fromFolder("/path/to/folder/");<br/>
     * Chain::init($keyStore)->fromCollection($collection)<br/>
     * Chain::init($keyStore)->fromAuthInfo()<br/>
     * Chain::init($keyStore)->fromUrl(['http//some.site/cert.crt', 'http//some2.site/cert2.crt'])<br/>
     *
     * @param KeyStore $keyStore
     * @return Chain
     */
    public static function init(KeyStore $keyStore): Chain
    {
        $chain = new self();
        $chain->keyStore = $keyStore;
        $chain->links = new CertCollection();
        return $chain;
    }

    /**
     * @throws Exception
     */
    public function fromSystem(): static
    {
        $ca_bundle = file_get_contents(openssl_get_cert_locations()['default_cert_file']);
        $matches = [];
        preg_match_all(
            '/(-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)/mi',
            $ca_bundle,
            $matches,
            PREG_SET_ORDER);
        $collection = new CertCollection();
        foreach ($matches as $cert){
            $cert = Certificate::loadFromString($cert[1]);
            $collection->addItem($cert);
        }
        return $this->fromCollection($collection);
    }

    /**
     * @throws Exception
     */
    public function fromFolder(string $path): static
    {
        if(!is_dir($path)) {
            throw new Exception("Path ($path) is not a folder or access problem.");
        }
        $collection = new CertCollection();
        $file_list = array_diff(scandir($path), ['.', '..']);
        foreach ($file_list as $value){
            $cert = Certificate::loadFromPath($path . "/" . $value);
            $collection->addItem($cert, $cert->getSubjectKeyIdentifier());
        }
        return $this->fromCollection($collection);
    }

    /**
     * @throws Exception
     */
    public function fromCollection(CertCollection $collection): static
    {
        //init lookup from user cert
        $cert = $this->keyStore->getCert();
        while($cert = $this->getNextCert($cert, $collection)) {
            $this->links->addItem($cert);
            if ($cert->isRootCert()) {
                $this->isReady = true;
                break;
            }
        }
        return $this;
    }

    /**
     * @throws Exception
     */
    public function fromAuthInfo(?Closure $loader = null): static
    {
        //init lookup from user cert
        $cert = $this->keyStore->getCert();

        if(isset($loader)) $this->certLoader = $loader;

        while($cert = $this->loadCert($cert)) {
            $this->links->addItem($cert);
            if ($cert->isRootCert()) {
                $this->isReady = true;
                break;
            }
        }
        return $this;
    }

    /**
     * @throws Exception
     */
    public function fromUrl(array $urls): static
    {
        $collection = new CertCollection();
        foreach ($urls as $url){
            $data = $this->getLoader()($url);
            $collection->addItem(Certificate::loadFromString($data));
        }
        return $this->fromCollection($collection);
    }

    public function isReady(): bool
    {
        return $this->isReady;
    }

    /**
     * Return intermediate and CA certs for load in Adapter
     * @return CertCollection
     */
    public function get(): CertCollection
    {
        return $this->links;
    }

    /**
     * Return full chain for display or debug
     * @return CertCollection
     */
    public function getFull(): CertCollection
    {
        $c = new CertCollection();
        $c->addItem($this->keyStore->getCert());
        foreach ($this->links->all() as $cert){
            $c->addItem($cert);
        }
        return $c;
    }

    /**
     * @throws Exception
     */
    private function getNextCert(Certificate $needle, CertCollection $collection): Certificate
    {
        foreach ($collection->all() as $cert) {
            if ($needle->getAuthorityKeyIdentifier() == $cert->getSubjectKeyIdentifier()) {
                return $cert;
            }
        }
        throw new Exception(
            "Not found Certificate for AuthorityKeyIdentifier ["
            . $needle->getAuthorityKeyIdentifier()
            ."]\n"
            .$needle->getAuthorityInfoAccess()
        );
    }

    /**
     * @throws Exception
     */
    private function loadCert(Certificate $cert): Certificate
    {
        $loaded_cert = $this->getLoader()($cert->getAuthorityUrl());
        if ($loaded_cert === false){
            throw new Exception(
                "Can't load Certificate for AuthorityKeyIdentifier [".$cert->getAuthorityKeyIdentifier()
                ."]\n"
                .$cert->getAuthorityInfoAccess()."\n".implode("\n", $cert->getIssuer())
            );
        }
        return Certificate::loadFromString($loaded_cert);
    }

    private function getLoader(): Closure
    {
        return $this->certLoader ?? function (string $url){
            $data = file_get_contents($url);
            if ($data === false){
                throw new Exception("Can't load Certificate from [ $url ]\n" );
            }
            return $data;
        };
    }

    public function getKeyStore(): KeyStore
    {
        return $this->keyStore;
    }

    /**
     * @throws Exception
     */
    public function validate(): Chain
    {
        foreach ($this->links->all() as $cert){
            $cert->validate();
        }
        $this->isValid = true;
        return $this;
    }

    public function isValid(): bool
    {
        return $this->isValid;
    }
}