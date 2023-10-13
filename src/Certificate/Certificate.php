<?php

namespace KalkanCrypt\Certificate;

use Exception;
use KalkanCrypt\Exception\AdapterException;
use KalkanCrypt\Flags\CertType;
use KalkanCrypt\Utils;
use function openssl_x509_parse;
use function openssl_x509_read;

class Certificate
{
    private const DER = 0x30;

    private CertType $type = CertType::CA;
    private string $path;

    private array $info;
    private string $raw;
    private string $pem = "";
    private ?string $realPath;

    /**
     * @throws Exception
     */
    private function __construct(string $raw, ?string $realPath = null)
    {
        $this->raw = $raw;
        $this->realPath = $realPath;
        $this->parseCert();
    }

    /**
     * @throws Exception
     */
    public function validate(): void
    {
        $this->validateDate();
    }

    /**
     * @throws Exception
     */
    private function validateDate(): void
    {
        $today = time();
        if ($this->getValidFromTS() > $today){
            throw new Exception('Cert valid date has not arrived');
        }
        if ($this->getValidToTS() < $today){
            throw new Exception('Cert valid date has passed'.print_r($this->getInfo(), true));
        }
    }

    /**
     * @throws Exception
     */
    public static function loadFromPath(string $path): static
    {
        if (!file_exists($path)){
            throw new Exception("File \"$path\" does not exists");
        }
        return new self(file_get_contents($path), $path);
    }

    /**
     * @throws Exception
     */
    public static function loadFromString(string $cert): static
    {
        return new self($cert);
    }

    /**
     * @throws Exception
     */
    private function parseCert(): void
    {
        if (ord($this->raw) == self::DER){
            $this->raw = Utils::der2pem($this->raw);
        }
        $parse = openssl_x509_parse(openssl_x509_read($this->raw));
        if (!$parse){
            throw new Exception("ERROR: Unable to parse cert $this->realPath \nMESSAGE: ".openssl_error_string());
        } else {
            $this->info = $parse;
        }

        if (isset($this->info['name'])){
            $this->info['name'] = Utils::string_decode($this->info['name']);
        }
        if (isset($this->info['extensions']['authorityKeyIdentifier'])){
            $this->info['extensions']['authorityKeyIdentifier'] = Utils::string_decode($this->info['extensions']['authorityKeyIdentifier']);
        }

        if (!openssl_x509_export($this->raw, $this->pem, false)){
            throw new Exception("Unable to export cert");
        }
        if ($this->type != CertType::USER && !$this->isRootCert()){
            $this->type = CertType::INTERMEDIATE;
        }

        //save raw to temporary file

        $this->path = "/tmp/".$this->info['hash'].".pem";
        fwrite(fopen($this->path, "w"), $this->raw);
    }

    /**
     * @throws AdapterException
     */
    public function getKalkanCert(): KalkanCert
    {
        return new KalkanCert($this->type, $this->raw);
    }

    public function isRootCert(): bool
    {
        return $this->getSubjectKeyIdentifier() == $this->getAuthorityKeyIdentifier();
    }
    public function getSerialNumber(){
        return $this->info['serialNumber']??null;
    }
    public function getSerialNumberHex(){
        return $this->info['serialNumberHex']??null;
    }

    public function getValidFrom(): ?string
    {
        return $this->info['validFrom']??null;
    }

    public function getValidTo(): ?string
    {
        return $this->info['validTo']??null;
    }

    public function getValidFromTS(): ?string
    {
        return $this->info['validFrom_time_t']??null;
    }
    public function getValidToTS(): ?string
    {
        return $this->info['validTo_time_t']??null;
    }

    public function getName(): ?string
    {
        return $this->info['name']??null;
    }

    public function getSubjectKeyIdentifier(bool $chunked = false): ?string
    {
        if (isset($this->info['extensions']['subjectKeyIdentifier'])){
            return $chunked ?
                $this->info['extensions']['subjectKeyIdentifier']
                : str_replace(":", "",$this->info['extensions']['subjectKeyIdentifier']);
        }
        return null;
    }

    public function getAuthorityKeyIdentifier(bool $chunked = false): ?string
    {
        if(isset($this->info['extensions']['authorityKeyIdentifier'])){
            $akid = trim(explode("\n", $this->info['extensions']['authorityKeyIdentifier'])[0]);

            $PREFIX = "keyid";

            if (str_starts_with($akid, $PREFIX)){
                $akid = substr($akid, strlen($PREFIX)+ 1);
            }
            return $chunked ? $akid : str_replace(":", "", $akid);
        }
        return null;
    }

    public function getAuthorityInfoAccess(): ?string
    {
        return $this->info['extensions']['authorityInfoAccess']??null;
    }

    /**
     * @throws Exception
     */
    public function getAuthorityUrl(): ?string
    {
        $url = null;
        if (!$this->isRootCert()){
            $matches = [];
            preg_match_all(
                '/(http[s]?:\/\/.*\.(?:cer|crt))/',
                $this->getAuthorityInfoAccess(),
                $matches, PREG_SET_ORDER);
            if (empty($matches)) throw new Exception('Not found url in authorityInfoAccess');
            return $matches[0][0];
        }
        return trim($url);
    }

    public function getRaw(): string
    {
        return $this->raw;
    }

    public function getIssuer(): ?array
    {
        return $this->info['issuer']??null;
    }

    public function getSubject(): ?array
    {
        return $this->info['subject']??null;
    }

    public function getSignAlg(): string
    {
        return substr($d = $this->pem, $s = strpos($d, "Signature Algorithm:") + 21, strpos($d, "\n", $s) - $s);
    }

    public function getInfo(bool $minimal = true): array
    {
        if ($minimal){
            return [
                "id" => $this->getSubjectKeyIdentifier(),
                "_id" => $this->getSubjectKeyIdentifier(true),
                "type" => $this->getType()->name,
                "path" => $this->getPath(),
                "valid_from" => date("d-m-Y H:i:s", $this->getValidFromTS()),
                "valid_to" => date("d-m-Y H:i:s", $this->getValidToTS()),
                "sign_alg" => $this->getSignAlg(),
                "is_root_cert" => $this->isRootCert()?'true':'false',
                "auth_key_id" => $this->getAuthorityKeyIdentifier(),
                "_auth_key_id" => $this->getAuthorityKeyIdentifier(true),
                "subject" => $this->getSubject(),
                "issuer" => $this->getIssuer(),
            ];
        }
        return $this->info;
    }

    public function getType(): CertType
    {
        return $this->type;
    }

    public function getPath(): ?string
    {
        return $this->path??null;
    }

    public function getRealPath(): string
    {
        return $this->realPath;
    }
}