<?php

namespace Spatie\Crypto\Rsa\Exceptions;

use Exception;

class CouldNotDecryptData extends Exception
{
    public static function make()
    {
        return new self("Could not decrypt the data.");
    }
}
