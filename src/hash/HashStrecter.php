<?php

namespace Soden46\GarudaCrypt\Hash;

use Soden46\GarudaCrypt\Hash\HashStretcherInterface as HasherContract;

/**
 * Class Hasher
 * @package Soden46\GarudaCrypt\Hash
 */
class Hasher implements HasherContract
{
    /**
     * Initiate constant for codename
     */
    const CODE = '::PIMEN::';


    /**
     * @param $key
     * @param $salt
     * @return mixed|string = 512-bits / 128 char
     */
    public function sha3($key, $salt)
    {
        $hashed = self::CODE . $key . $salt;
        return hash("sha3-512", $hashed);
    }

    /**
     * @param $key
     * @param $salt
     * @return mixed|string = 512-bits / 128 char
     */
    public function whirlpool($key, $salt)
    {
        $hashed = self::CODE . $key . $salt;
        return hash("whirlpool", $hashed);
    }

    /**
     * @param $key
     * @param $salt
     * @return mixed|string = 256-bits / 64 char
     */
    public function gost($key, $salt)
    {
        $hashed = self::CODE . $key . $salt;
        return hash("gost", $hashed);
    }

    /**
     * @param $key
     * @param $salt
     * @return string = 128-bits / 32 char
     */
    public function md5($key, $salt)
    {
        $hashed = self::CODE . $key . $salt;
        return hash("md5", $hashed);
    }

    /**
     * @param $key
     * @return string = 32-bits / 8 char
     *
     * This used for hashing Blowfish IV
     */
    public function joaat($key)
    {
        return hash("joaat", $key);
    }

    /**
     * @param $key
     * @param $salt
     * @return mixed|string
     */
    public function create($key, $salt)
    {

        $sha3 = self::sha3($key, $salt);
        $whirlpool = self::whirlpool($key, $salt);
        $gost = self::gost(($sha3 . $whirlpool), $salt);
        $md5 = self::md5($gost, $salt);

        $decode = base64_decode($md5);
        $hashed = "PIMEN::" . $decode . "=";

        return $hashed;
    }
}
