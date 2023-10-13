<?php
namespace KalkanCrypt\Flags;
use KalkanCrypt\Adapter;

interface ValidateType{
    const NOTHING = Adapter::KC_USE_NOTHING;
    const CRL = Adapter::KC_USE_CRL;
    const OCSP  = Adapter::KC_USE_OCSP;
}