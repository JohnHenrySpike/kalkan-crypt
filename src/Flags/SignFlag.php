<?php
namespace KalkanCrypt\Flags;
interface SignFlag
{

    const SIGN_DRAFT              =   0x1;
    const SIGN_CMS                =   0x2;
    const IN_PEM                  =   0x4;
    const IN_DER                  =   0x8;
    const IN_BASE64               =   0x10;
    const IN2_BASE64              =   0x20;
    const DETACHED_DATA           =   0x40;
    const WITH_CERT               =   0x80;
    const WITH_TIMESTAMP          =   0x100;
    const OUT_PEM                 =   0x200;
    const OUT_DER                 =   0x400;
    const OUT_BASE64              =   0x800;
    const IN_FILE                 =   0x8000;
    const NOCHECKCERTTIME         =   0x10000;
    const HASH_SHA256             =   0x20000;
    const HASH_GOST95             =   0x40000;
    const GET_OCSP_RESPONSE       =   0x80000;


    const XML_INCL_C14N           =   0x01000001;
    const XML_INCL_C14NCOMMENT    =   0x01000002;
    const XML_INCL_C14N11         =   0x01000004;
    const XML_INCL_C14N11COMMENT  =   0x01000008;
    const XML_EXCL_C14N           =   0x01000010;
    const XML_EXCL_C14NCOMMENT    =   0x01000020;
    const XMLC_INCL_C14N          =   0x01000040;
    const XMLC_INCL_C14NCOMMENT   =   0x01000080;
    const XMLC_INCL_C14N11        =   0x01000100;
    const XMLC_INCL_C14N11COMMENT =   0x01000200;
    const XMLC_EXCL_C14N          =   0x01000400;
    const XMLC_EXCL_C14NCOMMENT   =   0x01000800;

}