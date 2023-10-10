<?php

namespace KalkanCrypt;

use Exception;
use KalkanCrypt\Certificate\Certificate;
use KalkanCrypt\Exception\AdapterException;
use KalkanCrypt\Flags\StorageType;

class KeyStore
{
    private Certificate $cert;

    /**
     * @throws AdapterException
     * @throws Exception
     */
    public function __construct(private string $path, private string $password, private StorageType $storageType = StorageType::PKCS12)
    {
        if (!file_exists($path)){
            throw new Exception("File not exists");
        }
        $a = Adapter::getInstance();
        $a->loadKeyStore($storageType->value, $path, $password);
        $this->cert = Certificate::loadFromString($a->exportCertFromStore());
        $a->destroy();
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function getStorageType(): int
    {
        return $this->storageType->value;
    }

    public function getCert(): Certificate
    {
        return $this->cert;
    }
}