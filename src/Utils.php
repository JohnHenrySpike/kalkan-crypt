<?php

namespace KalkanCrypt;

class Utils
{
    static function der2pem($der_data): string
    {
        $pem = chunk_split(base64_encode($der_data), 64);
        return "-----BEGIN CERTIFICATE-----\n".$pem."-----END CERTIFICATE-----\n";
    }

    static function der2pem2($der_data): string
    {
        return chunk_split(base64_encode($der_data), 64);
    }
    static function pem2der($pem_data): bool|string
    {
        $begin = "CERTIFICATE-----";
        $end   = "-----END";
        $pem_data = substr($pem_data, strpos($pem_data, $begin)+strlen($begin));
        $pem_data = substr($pem_data, 0, strpos($pem_data, $end));
        return base64_decode($pem_data);
    }
    static function string_decode(string $str): array|string|null
    {
        $pattern = '/\\\x([0-9a-fA-F]{2})/';
        return preg_replace_callback(
            $pattern,
            function ($captures) {
                return chr(hexdec($captures[1]));
            },
            $str
        );
    }
}