<?php

namespace Soden46\GarudaCrypt;

use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Str;

class GarudaCrypt
{
    protected string $cipher = 'AES-256-CBC';

    public static function make(): Encrypter
    {
        $factory = new self;

        return new Encrypter($factory->key(), $factory->cipher);
    }

    protected function key(): string
    {
        $key = config('garuda.key');
        if (Str::contains($key, 'base64:')) {
            $key = substr($key, 9);
        }

        return base64_decode($key);
    }
}
