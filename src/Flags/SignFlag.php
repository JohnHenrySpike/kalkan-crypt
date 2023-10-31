<?php
namespace KalkanCrypt\Flags;
use KalkanCrypt\Adapter;

interface SignFlag
{

    const SIGN_DRAFT              =   Adapter::KC_SIGN_DRAFT;
    const SIGN_CMS                =   Adapter::KC_SIGN_CMS;
    const IN_PEM                  =   Adapter::KC_IN_PEM;
    const IN_DER                  =   Adapter::KC_IN_DER;
    const IN_BASE64               =   Adapter::KC_IN_BASE64;
    const IN2_BASE64              =   Adapter::KC_IN2_BASE64;
    const DETACHED_DATA           =   Adapter::KC_DETACHED_DATA;
    const WITH_CERT               =   Adapter::KC_WITH_CERT;
    const WITH_TIMESTAMP          =   Adapter::KC_WITH_TIMESTAMP;
    const OUT_PEM                 =   Adapter::KC_OUT_PEM;
    const OUT_DER                 =   Adapter::KC_OUT_DER;
    const OUT_BASE64              =   Adapter::KC_OUT_BASE64;
    const IN_FILE                 =   Adapter::KC_IN_FILE;
    const NO_CHECK_CERT_TIME      =   Adapter::KC_NOCHECKCERTTIME;
    const HASH_SHA256             =   Adapter::KC_HASH_SHA256;
    const HASH_GOST95             =   Adapter::KC_HASH_GOST95;
    const GET_OCSP_RESPONSE       =   Adapter::KC_GET_OCSP_RESPONSE;
    const HASH_GOST2015           =   Adapter::KC_HASH_GOST2015;


}