<?php

namespace Spatie\Crypto\Rsa;

class KeyPair
{
    protected $digestAlgorithm;
    protected $privateKeyBits;
    protected $privateKeyType;

    private $password = null;

    public function __construct(
        $digestAlgorithm = OPENSSL_ALGO_SHA512,
        $privateKeyBits = 4096,
        $privateKeyType = OPENSSL_KEYTYPE_RSA
    ) {
        $this->privateKeyType = $privateKeyType;
        $this->privateKeyBits = $privateKeyBits;
        $this->digestAlgorithm = $digestAlgorithm;
    }

    public function password($password = null)
    {
        $this->password = $password;

        return $this;
    }

    public function generate(
        $privateKeyPath = '',
        $publicKeyPath = ''
    ) {
        /** @var \OpenSSLAsymmetricKey $asymmetricKey */
        $asymmetricKey = openssl_pkey_new([
            "digest_alg" => $this->digestAlgorithm,
            "private_key_bits" => $this->privateKeyBits,
            "private_key_type" => $this->privateKeyType,
        ]);

        openssl_pkey_export(
            $asymmetricKey,
            $privateKey,
            $this->password,
        );

        $rawPublicKey = openssl_pkey_get_details($asymmetricKey);

        $publicKey = $rawPublicKey['key'];

        if ($privateKeyPath !== '') {
            file_put_contents($privateKeyPath, $privateKey);
        }

        if ($publicKeyPath !== '') {
            file_put_contents($publicKeyPath, $publicKey);
        }

        return [$privateKey, $publicKey];
    }
}
