<?php
namespace KalkanCrypt\Exception;
use Throwable;

class AdapterException extends \Exception
{
    public function __construct(string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        $matches = [];
        preg_match_all('/ERROR\s+(0x.*):\s+(.*)/m', $message, $matches, PREG_SET_ORDER);
        if (count($matches) == 2){
            $code = hexdec($matches[0][1]);
            $message = $matches[1][2];
        }
        parent::__construct($message, $code, $previous);
    }
}