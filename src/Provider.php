<?php
namespace KalkanCrypt;

use Exception;
use KalkanCrypt\Exception\AdapterException;

class Provider
{
    private Adapter $adapter;

    private Chain $chain;

    private bool $useTSA = false;
    private string $tsa_url;

    private Proxy $proxy;
    private bool $useProxy = false;

    private function __construct(){}

    private function __construct(){}

    /**
     * @throws Exception
     */
    public static function init(Chain $chain, ?string $tsa_url = null, Proxy $proxy = null): Provider
    {
        $d = new self();
        if (!$chain->isReady()) throw new Exception("Chain is not ready!");
        $d->chain = $chain;

        if (!empty($tsa_url)){
            $d->tsa_url = $tsa_url;
            $d->useTSA = true;
        }

        if ($proxy instanceof Proxy){
            $d->proxy = $proxy;
            $d->useProxy = true;
        }
        $d->fillAdapter();
        return $d;
    }

    /**
     * @throws AdapterException
     */
    public function signData(string $data, int $flags): string
    {
        return $this->adapter->signData( $data, $flags );
    }

    /**
     * @throws AdapterException
     */
    public function signXML(string $data, string $id, string $parentSignNode, string $parentNameSpace = "", $flags = 0): string
    {
        return $this->adapter->SignXML($data, $id, $parentSignNode, $parentNameSpace, $flags);
    }

    /**
     * @throws AdapterException
     */
    public function signWSSE(string $data, string $id, int $flags = 0): string
    {
        return $this->adapter->SignWSSE($data, $id, $flags);
    }

    /**
     * @throws AdapterException
     */
    public function signHash(string $data, int $flags): string
    {
        return $this->adapter->signHash( $data, $flags);
    }

    /**
     * @throws AdapterException
     */
    public function hashData(string $data, int $flags): string
    {
        return $this->adapter->hashData($data, $flags);
    }

    /**
     * @throws AdapterException
     */
    private function fillAdapter(): void
    {
        $this->adapter = Adapter::getInstance();

        if ($this->useTSA){
            $this->adapter->setTsaUrl($this->tsa_url);
        }

        if ($this->useProxy){
            $this->adapter->setProxy(
                $this->proxy->getType(),
                $this->proxy->getHost(),
                $this->proxy->getPort(),
                $this->proxy->getLogin(),
                $this->proxy->getPassword()
            );
        }

        $this->adapter->loadKeyStore(
            $this->chain->getKeyStore()->getStorageType(),
            $this->chain->getKeyStore()->getPath(),
            $this->chain->getKeyStore()->getPassword()
        );
        foreach ($this->chain->get()->all() as $item){
            $this->adapter->loadCertFromFile($item->getType()->value, $item->getPath());
        }
    }
}