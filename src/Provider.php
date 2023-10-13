<?php
namespace KalkanCrypt;

use Exception;
use KalkanCrypt\Exception\AdapterException;

class Provider
{
    private Adapter $adapter;

    private Chain $chain;

    private bool $isAdapterFilled = false;

    /**
     * @throws Exception
     */
    public static function init(Chain $chain): Provider
    {
        $d = new self();
        if (!$chain->isReady()) throw new Exception("Chain is not ready!");
        $d->chain = $chain;
        return $d;
    }

    /**
     * @throws AdapterException
     */
    public function signData(string $data, int $flags): string
    {
        $this->fillAdapter();
        return $this->adapter->signData( $data, $flags );
    }

    /**
     * @throws AdapterException
     */
    public function signXML(string $data, string $id, string $parentSignNode, string $parentNameSpace = "", $flags = 0): string
    {
        $this->fillAdapter();
        return $this->adapter->SignXML($data, $id, $parentSignNode, $parentNameSpace, $flags);
    }

    /**
     * @throws AdapterException
     */
    public function signWSSE(string $data, string $id, int $flags = 0): string
    {
        $this->fillAdapter();
        return $this->adapter->SignWSSE($data, $id, $flags);
    }

    /**
     * @throws AdapterException
     */
    private function fillAdapter(): void
    {
        if ($this->isAdapterFilled) return;
        $this->adapter = Adapter::getInstance();
        $this->adapter->loadKeyStore(
            $this->chain->getKeyStore()->getStorageType(),
            $this->chain->getKeyStore()->getPath(),
            $this->chain->getKeyStore()->getPassword()
        );
        foreach ($this->chain->get()->all()  as $item){
            $this->adapter->loadCertFromFile($item->getType()->value, $item->getPath());
        }
        $this->isAdapterFilled = true;
    }
}