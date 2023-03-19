<?php

namespace Soden46\GarudaCrypt\Commands;

use Illuminate\Console\Command;

class GarudaCryptCommand extends Command
{
    public $signature = 'garudacrypt:publish';

    public $description = 'Publish garudacrypt config file';

    public function handle()
    {
        $this->call('vendor:publish', ['--tag' => 'garudacrypt-config']);
    }
}
