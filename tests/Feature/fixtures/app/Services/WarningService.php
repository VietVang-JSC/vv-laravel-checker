<?php

declare(strict_types=1);

namespace App\Services;

class WarningService
{
    public function search()
    {
        return env('APP_ENV');
    }

    public function debug()
    {
        dd('stop here');
    }
}
