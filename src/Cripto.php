<?php

namespace elzobrito;

class Cripto
{
    public function cript($action, $dado, $password)
    {
        $method = 'aes-256-cbc';
        $password = substr(hash('sha256', $password, true), 0, 32);
        $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);

        $output = false;
        switch ($action) {
            case 'encrypt': {
                    $output = base64_encode(openssl_encrypt(trim($dado), $method, $password, OPENSSL_RAW_DATA, $iv));
                    break;
                }
            case 'decript': {
                    $output = openssl_decrypt(base64_decode(trim($dado)), $method, $password, OPENSSL_RAW_DATA, $iv);
                }
        }
        return $output;
    }

    public function encryptIt($dado, $password)
    {
        $this->cript('encrypt', $dado, $password);
    }

    public function decriptIt($dado, $password)
    {
        $this->cript('decript', $dado, $password);
    }
}
