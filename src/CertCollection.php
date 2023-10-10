<?php
namespace KalkanCrypt;

use Exception;
use KalkanCrypt\Certificate\Certificate;

class CertCollection
{
    /**
     * @var Certificate[]
     */
    private array $certs = [];

    /**
     * @throws Exception
     */
    public function __construct(array $certs = [])
    {
        foreach ($certs as $cert){
            if ($cert instanceof Certificate){
                $this->addItem($cert);
            } else {
                throw new Exception("Certificate is not instance of class KalkanCrypt\Certificate\Certificate");
            }
        }
    }

    public function addItem(Certificate $cert, ?string $key = null): void
    {
        if (is_null($key)){
            $this->certs[] = $cert;
        } else {
            $this->certs[$key] = $cert;
        }
    }

    public function getItem($key): ?Certificate
    {
        return $this->certs[$key] ?? null;
    }

    /**
     * @return Certificate[]
     */
    public function all(): array
    {
        return $this->certs;
    }
}