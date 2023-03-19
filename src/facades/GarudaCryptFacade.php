<?php

namespace Soden46\GarudaCrypt\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static mixed disk(string $disk)
 * @method static mixed key(string $key)
 * @method static mixed encrypt(string $sourceFile, string $destFile = null, $deleteSource = true)
 * @method static mixed encryptCopy(string $sourceFile, string $destFile = null)
 * @method static mixed decrypt(string $sourceFile, string $destFile = null, $deleteSource = true)
 * @method static mixed decryptCopy(string $sourceFile, string $destFile = null)
 *
 * @see \Soden46\GarudaCrypt\GarudaCrypt
 */
class GarudaCrypt extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'garuda-crypt';
    }
}
