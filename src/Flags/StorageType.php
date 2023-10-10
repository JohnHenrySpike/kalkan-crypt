<?php

namespace KalkanCrypt\Flags;

use KalkanCrypt\Adapter;

enum StorageType: int
{
    /**
     * Файловая система (небезопасный способ хранения ключей)
     * @var int
     */
    case PKCS12 = Adapter::KCST_PKCS12;
    /**
     * Удостоверение личности гражданина РК
     * @var int
     */
    case KZIDCARD = Adapter::KCST_KZIDCARD;
    /**
     * Казтокен
     * @var int
     */
    case KAZTOKEN = Adapter::KCST_KAZTOKEN;
    /**
     * eToken 72k
     * @var int
     */
    case ETOKEN72K  = Adapter::KCST_ETOKEN72K;
    /**
     * JaCarta
     * @var int
     */
    case JACARTA  = Adapter::KCST_JACARTA;
    /**
     * Сертификат X509
     * @var int
     */
    case X509CERT = Adapter::KCST_X509CERT;
    /**
     * aKey
     * @var int
     */
    case AKEY = Adapter::KCST_AKEY;

}