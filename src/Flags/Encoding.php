<?php
namespace KalkanCrypt\Flags;

enum Encoding: int
{
    case DER  = 0x101;
    case PEM  = 0x102;
    case B64  = 0x104;
}