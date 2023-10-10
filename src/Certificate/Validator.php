<?php

namespace KalkanCrypt\Certificate;

use KalkanCrypt\Exception\AdapterException;
use KalkanCrypt\Flags\ValidateType;
use KalkanCrypt\Provider;

class Validator
{
    private Certificate $cert;
    private Provider $provider;
    /**
     * @var int $type
     */
    private int $type = ValidateType::OCSP;
    private string $path = "http://test.pki.gov.kz/ocsp/";
    private array $result = [];
    public bool $isOk = true;


    public function __construct(Certificate $cert, Provider $provider)
    {
        $this->cert = $cert;
        $this->validate();
        $this->provider = $provider;
    }

    /**
     * @return void
     */
    private function validate(): void
    {
        try {
            $this->result =
                $this->provider->validateCert(
                    $this->cert->getRaw(),
                    $this->type,
                    $this->path,
                    Flag::KC_GET_OCSP_RESPONSE
                );
        } catch (AdapterException $e) {
            $this->isOk = false;
            $this->result[] = $e->getMessage();
        }
    }
    public function getResult(): array
    {
        return $this->result;
    }
}