<?php
namespace KalkanCrypt;

use KalkanCrypt\Flags\SignFlag;

class Provider
{
    private Adapter $adapter;

    private CertCollection $chain;
    private string $signedData = "";

    private KeyStore $keyStore;

    private bool $isAdapterFilled = false;

    public function signData(string $data, int $flags): string
    {
        $this->fillAdapter();
        return $this->adapter->signData( $data, $flags );
    }

    public function signXML(string $data, string $id, string $parentSignNode, string $parentNameSpace = "", $flags = 0): string
    {
        $this->fillAdapter();
        return $this->adapter->SignXML($data, $id, $parentSignNode, $parentNameSpace, $flags);
    }

    public function signWSSE(string $data, string $id, int $flags = 0): string
    {
        $this->fillAdapter();
        return $this->adapter->SignWSSE($data, $id, $flags);
    }

    public function getKeyStore(): KeyStore
    {
        return $this->keyStore;
    }

    public function setKeyStore(KeyStore $keyStore): Provider
    {
        $this->keyStore = $keyStore;
        return $this;
    }

    public function loadChain(CertCollection $certs = new CertCollection(), bool $tryLoad = false): void
    {
        $this->chain = CertManager::createChain($this->keyStore->getCert(), $certs, $tryLoad);
    }

    public function fillAdapter(): void
    {
        if ($this->isAdapterFilled) return;
        $this->adapter = Adapter::getInstance();
        $this->adapter->loadKeyStore(
            $this->keyStore->getStorageType(),
            $this->keyStore->getPath(),
            $this->keyStore->getPassword()
        );
        foreach ($this->chain->all()  as $item){
            $this->adapter->loadCertFromFile($item->getType()->value, $item->getPath());
        }
        $this->isAdapterFilled = true;
    }

    public function getChain(): CertCollection
    {
        return $this->chain;
    }

    public function getChainPretty(): array
    {
        $certs = [];
        $chainLinks = [];
        foreach (array_merge([$this->keyStore->getCert()], $this->chain->all()) as $item){
            $chainLinks[] = $item->getSubjectKeyIdentifier();
            $certs[] = $item->getInfo();
        }
        return ["chainLinks" => $chainLinks, "certs" => $certs];
    }

}