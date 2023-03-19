<?php

namespace Soden46\GarudaCrypt\Tests;

use Illuminate\Support\Facades\Storage;
use Orchestra\Testbench\TestCase;
use Soden46\GarudaCrypt\Facades\GarudaCrypt;
use Soden46\GarudaCrypt\GarudaCryptServiceProvider;

class GarudaCryptTest extends TestCase
{
    /**
     * Get package providers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     *
     * @return array
     */
    protected function getPackageProviders($app)
    {
        return [
            GarudaCryptServiceProvider::class,
        ];
    }

    /**
     * Get package aliases.
     *
     * @param  \Illuminate\Foundation\Application  $app
     *
     * @return array
     */
    protected function getPackageAliases($app)
    {
        return [
            'GarudaCrypt' => GarudaCrypt::class,
        ];
    }

    /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function getEnvironmentSetUp($app)
    {
        // Set the storage local filesystem
        $app['config']->set('filesystems.disks.local.driver', 'local');
        $app['config']->set('filesystems.disks.local.root', realpath(__DIR__ . '/../storage/app'));
        $app['config']->set('filesystems.default', 'local');

        // Generate and set a random encryption key
        $app['config']->set('garuda-crypt.key', $this->generateRandomKey());
    }

    /**
     * Generate a random key for the application.
     *
     * @return string
     */
    protected function generateRandomKey()
    {
        return 'base64:' . base64_encode(
            \Soden46\GarudaCrypt\GarudaCrypt::generateKey()
        );
    }

    /**
     * Generate a file with random contents.
     *
     * @return int|bool
     */
    protected function generateFile($fileName, $fileSize = 500000)
    {
        $fileContents = random_bytes($fileSize);

        return Storage::put($fileName, $fileContents);
    }

    /** @test */
    public function test_encrypt_generates_a_file()
    {
        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::encrypt($fileName);

        // Test if the encrypted file exists
        $this->assertFileExists(
            Storage::path("{$fileName}.enc")
        );
    }

    /** @test */
    public function test_encrypt_copy_generates_a_file()
    {
        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::encryptCopy($fileName);

        // Test if the encrypted file exists
        $this->assertFileExists(
            Storage::path("{$fileName}.enc")
        );
    }

    /** @test */
    public function test_it_can_encrypt_a_file_using_a_different_destination_name()
    {
        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::encrypt($fileName, 'encrypted.enc');

        // Test if the encrypted file exists
        $this->assertFileExists(
            Storage::path('encrypted.enc')
        );
    }

    /** @test */
    public function test_encrypt_deletes_the_original()
    {
        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::encrypt($fileName);

        // Test if the original file has been deleted
        $this->assertFileNotExists(
            Storage::path($fileName)
        );
    }

    /** @test */
    public function test_encrypt_copy_keeps_the_original()
    {
        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::encryptCopy($fileName);

        // Test if the original file still exists
        $this->assertFileExists(
            Storage::path($fileName)
        );
    }

    /** @test */
    public function test_decrypt()
    {
        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::encrypt($fileName);
        GarudaCrypt::decrypt("{$fileName}.enc");

        // Test that the decrypted file was generated
        $this->assertFileExists(
            Storage::path($fileName)
        );
    }

    /** @test */
    public function test_decrypt_using_a_different_destination_name()
    {
        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::encrypt($fileName);
        GarudaCrypt::decrypt("{$fileName}.enc", "{$fileName}.dec");

        // Test that the decrypted file was generated
        $this->assertFileExists(
            Storage::path("{$fileName}.dec")
        );
    }

    /** @test */
    public function test_decrypt_deletes_the_encrypted_file()
    {
        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::encrypt($fileName);
        GarudaCrypt::decrypt("{$fileName}.enc");

        // Test that the encrypted file was deleted after decryption
        $this->assertFileNotExists(
            Storage::path("{$fileName}.enc")
        );
    }

    /** @test */
    public function test_decrypt_copy_keeps_the_encrypted_file()
    {
        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::encrypt($fileName);
        GarudaCrypt::decryptCopy("{$fileName}.enc");

        // Test that the encrypted file was deleted after decryption
        $this->assertFileExists(
            Storage::path("{$fileName}.enc")
        );
    }

    /** @test */
    public function test_a_decrypted_file_has_the_same_content_as_the_original_file()
    {
        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::encryptCopy($fileName);
        GarudaCrypt::decrypt("{$fileName}.enc", "{$fileName}.dec");

        // Test to see if the decrypted content is the same as the original
        $this->assertEquals(
            Storage::get($fileName),
            Storage::get("{$fileName}.dec")
        );
    }

    /** @test */
    public function test_it_can_encrypt_and_decrypt_using_a_user_generated_key()
    {
        $key = GarudaCrypt::generateKey();

        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::key($key)->encryptCopy($fileName);
        GarudaCrypt::key($key)->decrypt("{$fileName}.enc", "{$fileName}.dec");

        // Test to see if the decrypted content is the same as the original
        $this->assertEquals(
            Storage::get($fileName),
            Storage::get("{$fileName}.dec")
        );
    }

    /** @test */
    public function test_it_can_stream_a_decrypted_file()
    {
        $this->generateFile($fileName = 'file.txt');

        GarudaCrypt::encryptCopy($fileName);

        ob_start();
        GarudaCrypt::streamDecrypt("{$fileName}.enc");
        $phpOutput = ob_get_contents();
        ob_end_clean();

        // Test to see if the decrypted content is sent to php://output
        $this->assertEquals(
            Storage::get($fileName),
            $phpOutput
        );
    }

    public function tearDown(): void
    {
        // Cleanup the storage dir
        array_map('unlink', glob(__DIR__ . '/../storage/app/*.*'));

        parent::tearDown();
    }
}
