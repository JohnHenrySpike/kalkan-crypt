<?php
namespace KalkanCrypt\Flags;
use KalkanCrypt\Adapter;

enum CertType: int
{
    /**
     * Корневой сертификат УЦ
     * @var int
     */
    case CA = Adapter::KC_CERT_CA;
    /**
     * Сертификат промежуточного УЦ
     * @var int
     */
    case INTERMEDIATE = Adapter::KC_CERT_INTERMEDIATE;
    /**
     * Сертификат пользователя
     * @var int
     */
    case USER = Adapter::KC_CERT_USER;
    
}