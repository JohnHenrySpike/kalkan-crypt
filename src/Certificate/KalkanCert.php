<?php

namespace KalkanCrypt\Certificate;

use KalkanCrypt\Adapter;
use KalkanCrypt\Exception\AdapterException;
use KalkanCrypt\Flags\CertProp;
use KalkanCrypt\Flags\CertType;

class KalkanCert
{
    private string $cert;
    private array $ar_cert;

    /**
     * @throws AdapterException
     */
    public function __construct(private readonly CertType $type, string $cert)
    {
        $this->cert = $cert;
        $this->loadProps();
    }

    /**
     * @throws AdapterException
     */
    public static function load(CertType $type, string $cert): KalkanCert
    {
        return new self($type, $cert);
    }

    public function getInfo(): array
    {
        return $this->ar_cert;
    }

    /**
     * @throws AdapterException
     */
    private function loadProps(): void
    {
        $a = Adapter::getInstance();
        $prop_list = CertProp::cases();

        foreach ($prop_list as $prop) {
            if (in_array($prop, [CertProp::OCSP, CertProp::GET_CRL, CertProp::GET_DELTA_CRL])) continue; //TODO: remove when fixed
            $this->ar_cert[$prop->name] = $a->getCertInfo($prop->value, $this->cert);
        }
    }

    public function getCert(): string
    {
        return $this->cert;
    }

    public function getIssuer(): array
    {
        $props = [];
        foreach (CertProp::cases() as $case){
            if (str_starts_with($case->name, "ISSUER_")){
                $key = substr($case->name, strpos($case->name, "_")+1);
                $props[$key] = $this->ar_cert[$case->name]??null;
            }
        }
        return $props;
    }

    public function getSubject(): array
    {
        $props = [];
        foreach (CertProp::cases() as $case){
            if (str_starts_with($case->name, "SUBJECT_")){
                $key = substr($case->name, strpos($case->name, "_")+1);
                $props[$key] = $this->ar_cert[$case->name]??null;
            }
        }
        return $props;
    }

    public function getValidFrom(): ?string
    {
        return $this->ar_cert[CertProp::NOTBEFORE->name]?$this->parseAttr($this->ar_cert[CertProp::NOTBEFORE->name]):null;
    }

    public function getValitdTo(): ?string
    {
        return $this->ar_cert[CertProp::NOTAFTER->name]?$this->parseAttr($this->ar_cert[CertProp::NOTAFTER->name]):null;
    }

    public function getAuthKeyId(): ?string
    {
        return $this->ar_cert[CertProp::AUTH_KEY_ID->name]?$this->parseAttr($this->ar_cert[CertProp::AUTH_KEY_ID->name]):null;
    }

    public function getSubjKeyId(): ?string
    {
        return $this->ar_cert[CertProp::SUBJ_KEY_ID->name]?$this->parseAttr($this->ar_cert[CertProp::SUBJ_KEY_ID->name]):null;
    }

    public function getSerialNumber(): ?string
    {
        return $this->ar_cert[CertProp::CERT_SN->name]?$this->parseAttr($this->ar_cert[CertProp::CERT_SN->name]):null;
    }

    public function getSignAlg(): ?string
    {
        return $this->ar_cert[CertProp::SIGNATURE_ALG->name]?$this->parseAttr($this->ar_cert[CertProp::SIGNATURE_ALG->name]):null;
    }

    public function getPublicKey(){
        return $this->ar_cert[CertProp::PUBKEY->name]??null;
    }

    private function parseAttr(string $attr): string
    {
        return substr($attr, strpos($attr, "=") + 1); //, strlen($attr)
    }
}