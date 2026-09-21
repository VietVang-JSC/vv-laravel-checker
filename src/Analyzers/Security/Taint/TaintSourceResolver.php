<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security\Taint;

/**
 * Resolves short-class / facade names to their fully-qualified class names
 * using a purely string-based map. No autoload reflection is performed, which
 * keeps the package dependency-light and fast.
 *
 * Assumptions / limitations:
 *  - Only a fixed set of well-known Laravel facades are mapped by default.
 *  - Custom aliases or `use` imports pointing to different classes are not
 *    honoured; resolution relies solely on the short name map.
 *  - Namespaced calls (e.g. `\Illuminate\Support\Facades\DB::raw()`) are
 *    resolved directly from the FQN without consulting the map.
 *  - Unknown short names resolve to `null`, signalling "not a recognised
 *    sink source" to the taint engine.
 */
final class TaintSourceResolver
{
    private const DEFAULT_FACADES = [
        'DB' => 'Illuminate\Support\Facades\DB',
        'Schema' => 'Illuminate\Support\Facades\Schema',
        'Cache' => 'Illuminate\Support\Facades\Cache',
        'Redis' => 'Illuminate\Support\Facades\Redis',
        'User' => 'Illuminate\Support\Facades\Auth',
        'Auth' => 'Illuminate\Support\Facades\Auth',
        'Hash' => 'Illuminate\Support\Facades\Hash',
        'Session' => 'Illuminate\Support\Facades\Session',
        'Cookie' => 'Illuminate\Support\Facades\Cookie',
        'Config' => 'Illuminate\Support\Facades\Config',
        'Route' => 'Illuminate\Support\Facades\Route',
        'Request' => 'Illuminate\Support\Facades\Request',
        'Log' => 'Illuminate\Support\Facades\Log',
        'Validator' => 'Illuminate\Support\Facades\Validator',
        'Mail' => 'Illuminate\Support\Facades\Mail',
        'Storage' => 'Illuminate\Support\Facades\Storage',
        'File' => 'Illuminate\Support\Facades\File',
        'App' => 'Illuminate\Support\Facades\App',
        'Artisan' => 'Illuminate\Support\Facades\Artisan',
        'Event' => 'Illuminate\Support\Facades\Event',
        'Queue' => 'Illuminate\Support\Facades\Queue',
        'Bus' => 'Illuminate\Support\Facades\Bus',
        'Blade' => 'Illuminate\Support\Facades\Blade',
        'Broadcast' => 'Illuminate\Support\Facades\Broadcast',
        'URL' => 'Illuminate\Support\Facades\URL',
        'View' => 'Illuminate\Support\Facades\View',
        'Gate' => 'Illuminate\Support\Facades\Gate',
        'Notification' => 'Illuminate\Support\Facades\Notification',
        'RateLimiter' => 'Illuminate\Support\Facades\RateLimiter',
        'Process' => 'Illuminate\Support\Facades\Process',
        'Http' => 'Illuminate\Support\Facades\Http',
        'Date' => 'Illuminate\Support\Facades\Date',
        'Crypt' => 'Illuminate\Support\Facades\Crypt',
        'Password' => 'Illuminate\Support\Facades\Password',
        'ThrottleRequests' => 'Illuminate\Routing\Middleware\ThrottleRequests',
        'Elixir' => 'Illuminate\Support\Facades\Elixir',
    ];

    private array $facades;

    /**
     * @param array<string, string> $extraFacades Additional short-name -> FQN map entries.
     */
    public function __construct(array $extraFacades = [])
    {
        $this->facades = array_merge(self::DEFAULT_FACADES, $extraFacades);
    }

    /**
     * Resolve a (possibly qualified) callable name to its FQN, or null if unknown.
     */
    public function resolve(string $name): ?string
    {
        $name = ltrim($name, '\\');

        if (str_contains($name, '\\')) {
            return $this->normalize($name);
        }

        return isset($this->facades[$name])
            ? $this->normalize($this->facades[$name])
            : null;
    }

    /**
     * Return true when the resolved FQN belongs to the given short name or its FQN.
     */
    public function isShortName(string $resolved, string $shortName): bool
    {
        $fqn = $this->facades[$shortName] ?? null;
        if ($fqn === null) {
            return false;
        }

        return $this->normalize($resolved) === $this->normalize($fqn);
    }

    /**
     * @return array<string, string> The currently known facade map.
     */
    public function map(): array
    {
        return $this->facades;
    }

    private function normalize(string $fqn): string
    {
        return ltrim($fqn, '\\');
    }
}
