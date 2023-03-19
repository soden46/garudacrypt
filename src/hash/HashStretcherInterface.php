<?php

namespace Soden46\GarudaCrypt\Hash;

/**
 * Interface HashStretcherInterface
 * @package Soden46\GarudaCrypt\Hash
 */
interface HashStretcherInterface
{

    /**
     * @param $key
     * @param $salt
     * @return mixed
     */
    public function sha3($key, $salt);

    /**
     * @param $key
     * @param $salt
     * @return mixed
     */
    public function whirlpool($key, $salt);

    /**
     * @param $key
     * @param $salt
     * @return mixed
     */
    public function gost($key, $salt);

    /**
     * @param $key
     * @return mixed
     */
    public function joaat($key);

    /**
     * @param $key
     * @param $salt
     * @return mixed
     */
    public function create($key, $salt);
}
