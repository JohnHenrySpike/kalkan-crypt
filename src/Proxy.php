<?php

namespace KalkanCrypt;

class Proxy
{
    const ON = Adapter::KC_PROXY_ON;
    const AUTH = Adapter::KC_PROXY_AUTH;

    private string $host;
    private int $port;
    private string $login;
    private string $password;

    private int $type = self::ON;

    public function __construct(string $host, int $port, ?string $login = null, ?string $password = null)
    {
        $this->host = $host;
        $this->port = $port;
        if (!empty($login) && empty($password)){
            $this->login = $login;
            $this->password = $password;
            $this->type = self::AUTH;
        }
    }

    public function getPassword(): string
    {
        return $this->password??"";
    }

    public function getLogin(): string
    {
        return $this->login??"";
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function getType(): int
    {
        return $this->type;
    }

    public function getHost(): string
    {
        return $this->host;
    }
}