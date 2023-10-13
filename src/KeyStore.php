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
    private function __construct(private string $path, private string $password, private StorageType $storageType = StorageType::PKCS12)
    {
        $a = Adapter::getInstance();
        $a->loadKeyStore($storageType->value, $path, $password);
        $this->cert = Certificate::loadFromString($a->exportCertFromStore());
        $a->destroy();
    }

    /**
     * @throws AdapterException
     * @throws Exception
     */
    public static function load(string $path, string $password, StorageType $storageType = StorageType::PKCS12): KeyStore
    {
        if (!file_exists($path)){
            throw new Exception("File $path not exists");
        }
        return new self($path, $password, $storageType);
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