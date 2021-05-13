<?php

namespace Spatie\Crypto\Rsa;

use Spatie\Crypto\Rsa\Exceptions\CouldNotDecryptData;
use Spatie\Crypto\Rsa\Exceptions\FileDoesNotExist;
use Spatie\Crypto\Rsa\Exceptions\InvalidPrivateKey;

class PrivateKey
{
    /** @var resource */
    protected $privateKey;

    public static function fromString(string $privateKeyString, string $password = null)
    {
        return new static($privateKeyString, $password);
    }

    public static function fromFile(string $pathToPrivateKey, string $password = null)
    {
        if (! file_exists($pathToPrivateKey)) {
            throw FileDoesNotExist::make($pathToPrivateKey);
        }

        $privateKeyString = file_get_contents($pathToPrivateKey);

        return new static($privateKeyString, $password);
    }

    public function __construct(string $privateKeyString, string $password = null)
    {
        $this->privateKey = openssl_pkey_get_private($privateKeyString, $password);

        if ($this->privateKey === false) {
            throw InvalidPrivateKey::make();
        }
    }

    public function encrypt(string $data)
    {
        openssl_private_encrypt($data, $decrypted, $this->privateKey, OPENSSL_PKCS1_PADDING);

        return $decrypted;
    }

    public function canDecrypt(string $data)
    {
        try {
            $this->decrypt($data);
        } catch (CouldNotDecryptData $exception) {
            return false;
        }

        return true;
    }

    public function decrypt(string $data)
    {
        openssl_private_decrypt($data, $decrypted, $this->privateKey, OPENSSL_PKCS1_OAEP_PADDING);

        if (is_null($decrypted)) {
            throw CouldNotDecryptData::make();
        }

        return $decrypted;
    }

    public function details()
    {
        return openssl_pkey_get_details($this->privateKey);
    }

    public function sign(string $data): string
    {
        openssl_sign($data, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

        return base64_encode($signature);
    }
}
