<?php
namespace KalkanCrypt\Flags;

use KalkanCrypt\Adapter;

enum Encoding: int
{
    case DER  = Adapter::KC_CERT_DER;
    case PEM  = Adapter::KC_CERT_PEM;
    case B64  = Adapter::KC_CERT_B64;
}