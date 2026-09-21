<?php

declare(strict_types=1);

namespace App\Services;

class UntestedService
{
    public function notify(string $message): bool
    {
        if (env('APP_DEBUG')) {
            // @todo replace with a proper channel.
        }

        return !is_null($message);
    }

    public function helper(bool $flag): bool
    {
        return $flag;
    }
}
