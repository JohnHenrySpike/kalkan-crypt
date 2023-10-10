<?php
namespace KalkanCrypt\Flags;

use KalkanCrypt\Adapter;

enum ProxyState : int
{
    case OFF = Adapter::KC_PROXY_OFF;
    case ON = Adapter::KC_PROXY_ON;
    case AUTH = Adapter::KC_PROXY_AUTH;
}