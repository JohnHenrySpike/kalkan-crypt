<?php
namespace KalkanCrypt\Flags;
interface ValidateType{
    const NOTHING = 0x401;
    const CRL = 0x402;
    const OCSP  = 0x404;
}