<?php

return [

    /*
     * The default key used for all file encryption / decryption
     * This package will look for a SHA256_KEY and GARUDA_CRYPT_KEY in your env file
     * If no SHA256_KEY and GARUDA_CRYPT_KEY is found, then it will use your Laravel APP_KEY
     */
    'key' => env('GARUDA_CRYPT_KEY', env('APP_KEY')),
    'sha' =>  env('SHA256_KEY', env('APP_KEY')),

    /*
     * The cipher used for encryption.
     * Supported options are AES-128-CBC and AES-256-CBC
     */
    'cipher' => 'AES-256-CBC',

    /*
     * The Storage disk used by default to locate your files.
     */
    'disk' => 'local',
    'adapter' => 'disk',
];
