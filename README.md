# Garuda encryption / decryption in Laravel

[![Latest Version on Packagist](https://img.shields.io/packagist/v/soden46/garudacrypt.svg?style=flat-square)](https://packagist.org/packages/soden46/garudacrypt)
[![MIT Licensed](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Total Downloads](https://img.shields.io/packagist/dt/soden46/garudacrypt.svg?style=flat-square)](https://packagist.org/packages/soden46/garudacrypt)

With this package, you can encrypt and decrypt files of any size in your Laravel project. This package uses streams and [CBC encryption](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)), encrypting / decrypting a segment of data at a time.


## Installation and usage

This package requires PHP 8.0 and Laravel 9.0 or higher.  

You can install the package via composer:

```bash
composer require soden46/garudacrypt
```

## Usage

### Tutorials
For a detailed description of how to encrypt files in Laravel using this package, please see the following articles:


### Description
This package will automatically register a facade called `GarudaCrypt`. The `GarudaCrypt` facade is using the Laravel `Storage` and will allow you to specify a `disk`, just as you would normally do when working with Laravel Storage. All file names/paths that you will have to pass into the package encrypt/decrypt functions are relative to the disk root folder. By default, the `local` disk is used, but you can either specify a different disk each time you call one of `GarudaCrypt` methods, or you can set the default disk to something else, by publishing this package's config file.

If you want to change the default `disk` or change the `key`/`cipher` used for encryption, you can publish the config file:

```
php artisan vendor:publish --provider="Soden46\GarudaCrypt\GarudaCryptServiceProvider"
```

This is the contents of the published file:
``` php
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
];
```


### Encrypting a file

The `encrypt` method will search for a file, encrypt it and save it in the same directory, while deleting the original file.

``` php
public function encrypt(string $sourceFile, string $destFile = null, $deleteSource = true)
```

The `encryptCopy` method will search for a file, encrypt it and save it in the same directory, while preserving the original file.

``` php
public function encryptCopy(string $sourceFile, string $destFile = null)
```


#### Examples:

The following example will search for `file.txt` into the `local` disk, save the encrypted file as `file.txt.enc` and delete the original `file.txt`:
``` php
GarudaCrypt::encrypt('file.txt');
```

You can also specify a different `disk`, just as you would normally with the Laravel `Storage` facade:
``` php
GarudaCrypt::disk('s3')->encrypt('file.txt');
```

You can also specify a different name for the encrypted file by passing in a second parameter. The following example will search for `file.txt` into the `local` disk, save the encrypted file as `encrypted.txt` and delete the original `file.txt`:
``` php
GarudaCrypt::encrypt('file.txt', 'encrypted.txt');
```

The following examples both achive the same results as above, with the only difference that the original file is not deleted:
``` php
// save the encrypted copy to file.txt.enc
GarudaCrypt::encryptCopy('file.txt');

// or save the encrypted copy with a different name
GarudaCrypt::encryptCopy('file.txt', 'encrypted.txt');
```

### Decrypting a file

The `decrypt` method will search for a file, decrypt it and save it in the same directory, while deleting the encrypted file.

``` php
public function decrypt(string $sourceFile, string $destFile = null, $deleteSource = true)
```

The `decryptCopy` method will search for a file, decrypt it and save it in the same directory, while preserving the encrypted file.

``` php
public function decryptCopy(string $sourceFile, string $destFile = null)
```

#### Examples:

The following example will search for `file.txt.enc` into the `local` disk, save the decrypted file as `file.txt` and delete the encrypted file `file.txt.enc`:
``` php
GarudaCrypt::decrypt('file.txt.enc');
```

If the file that needs to be decrypted doesn't end with the `.enc` extension, the decrypted file will have the `.dec` extention. The following example will search for `encrypted.txt` into the `local` disk, save the decrypted file as `encrypted.txt.dec` and delete the encrypted file `encrypted.txt`:
``` php
GarudaCrypt::decrypt('encrypted.txt');
```

As with the encryption, you can also specify a different `disk`, just as you would normally with the Laravel `Storage` facade:
``` php
GarudaCrypt::disk('s3')->decrypt('file.txt.enc');
```

You can also specify a different name for the decrypted file by passing in a second parameter. The following example will search for `encrypted.txt` into the `local` disk, save the decrypted file as `decrypted.txt` and delete the original `encrypted.txt`:
``` php
GarudaCrypt::decrypt('encrypted.txt', 'decrypted.txt');
```

The following examples both achive the same results as above, with the only difference that the original (encrypted) file is not deleted:
``` php
// save the decrypted copy to file.txt while preserving file.txt.enc
GarudaCrypt::decryptCopy('file.txt.enc');

// or save the decrypted copy with a different name, while preserving the file.txt.enc
GarudaCrypt::decryptCopy('file.txt.enc', 'decrypted.txt');
```

### Streaming a decrypted file

Sometimes you will only want to allow users to download the decrypted file, but you don't need to store the actual decrypted file. For this, you can use the `streamDecrypt` function that will decrypt the file and will write it to the `php://output` stream. You can use the Laravel [`streamDownload` method](https://laravel.com/docs/6.x/responses#file-downloads) (available since 5.6) in order to generate a downloadable response:

``` php
return response()->streamDownload(function () {
    GarudaCrypt::streamDecrypt('file.txt')
}, 'laravel-readme.md');
```

### Using a different key for each file

You may need to use different keys to encrypt your files. You can explicitly specify the key used for encryption using the `key` method.

``` php
GarudaCrypt::key($encryptionKey)->encrypt('file.txt');
```

Please note that the encryption key must be 16 bytes long for the `AES-128-CBC` cipher and 32 bytes long for the `AES-256-CBC` cipher.

You can generate a key with the correct length (based on the cipher specified in the config file) by using the `generateKey` method:

``` php
$encryptionKey = GarudaCrypt::generateKey();
```

## Testing

Run the tests with:

``` bash
composer test
```

### Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

### Security

If you discover any security related issues, please email syarifsoden22@gmail.com instead of using the issue tracker.

## Credits

- [Syarif Syarifuddin](https://github.com/soden46)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.