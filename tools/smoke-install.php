<?php

/**
 * End-to-end check of the distributed artifact.
 *
 * The unit and feature suites run from a clone of this repository, where
 * `bin/quality-check` finds `vendor/autoload.php` one directory up and
 * `tests/`, `.github/` and the dev configs are simply present. Neither is true
 * for an installed package: Composer hoists dependencies, and the archive only
 * carries what `.gitattributes` does not export-ignore.
 *
 * That gap shipped a broken `vendor/bin/quality-check` for everyone who followed
 * the README's `composer require`, and a 19 MB archive, and nothing in the test
 * suite noticed. This script closes it: it builds the archive, asserts the
 * contents are the runtime subset, installs it into a throwaway project from
 * that archive, runs the installed binary against a known-bad app, and checks
 * the findings and the version stamp.
 *
 * Usage: composer smoke      (or: php tools/smoke-install.php)
 */

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$checks = 0;

$say = static function (string $message) use (&$checks): void {
    $checks++;
    echo '  ' . $message . PHP_EOL;
};

$fail = static function (string $message) use (&$failures): void {
    $failures[] = $message;
    echo '  FAIL  ' . $message . PHP_EOL;
};

$cleanup = static function (string $directory) use (&$checks): void {
    if (!is_dir($directory)) {
        return;
    }

    $checks++;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($iterator as $item) {
        $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
    }

    @rmdir($directory);
};

$composer = null;
foreach (['composer', 'composer.bat', 'composer.phar'] as $candidate) {
    $path = $root . DIRECTORY_SEPARATOR . $candidate;
    if (is_file($path)) {
        $composer = $path;
        break;
    }
}

$composerCommand = $composer ?? (PHP_OS_FAMILY === 'Windows' ? 'composer.bat' : 'composer');

$workspace = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-smoke-' . bin2hex(random_bytes(4));
$distDir = $workspace . '/dist';
$projectDir = $workspace . '/project';

if (PHP_SAPI === 'cli' && getenv('SMOKE_DEBUG') === '1') {
    echo 'composer command: ' . $composerCommand . PHP_EOL;
}

// Two traps live in the child process, and both cost real time to diagnose:
//
//  1. Composer's parallel downloader stalls indefinitely when its stdout/stderr
//     are pipes that proc_open created on Windows. Reproduced here: the same
//     `composer install`, same fresh cache, same machine — seconds from a
//     console, and a permanent stall after the last download (40 half-written
//     vendor/composer/tmp-*.zip files, no further output) when the parent is PHP.
//     So the child's output goes to files, never to pipes.
//  2. COMPOSER_PROCESS_TIMEOUT only covers network requests, so it cannot stop a
//     stall that happens after the last byte of output. $run enforces a
//     wall-clock deadline of its own and reports whatever the child last said.
//
// The child also gets a private cache directory, so a developer's own concurrent
// `composer install` cannot serialise against it.
$env = getenv();
$env['COMPOSER_CACHE_DIR'] = $workspace . '/composer-cache';
$env['COMPOSER_NO_INTERACTION'] = '1';
$env['COMPOSER_PROCESS_TIMEOUT'] = '300';
$env['COMPOSER_DISABLE_XDEBUG_WARN'] = '1';

$debug = PHP_SAPI === 'cli' && getenv('SMOKE_DEBUG') === '1';

// SMOKE_TIMEOUT exists so the stall path itself can be exercised: set it to 1 and
// the composer install is killed mid-flight, which is the only way to check that
// the kill takes the whole tree and leaves nothing behind.
$childTimeout = max(1, (int) (getenv('SMOKE_TIMEOUT') ?: 300));

$run = static function (array|string $command, string $cwd, int $timeout = 0) use (&$env, $debug, $childTimeout): array {
    $timeout = $timeout > 0 ? $timeout : $childTimeout;
    // An array command bypasses the shell, which cannot execute composer's
    // .bat wrapper on Windows — it gets handed to php.exe instead and dies with
    // "Could not open input file". Composer calls therefore go through a shell
    // string; only the PHP_BINARY invocations use the array form.
    $label = substr(md5((is_array($command) ? implode(' ', $command) : $command) . microtime()), 0, 8);
    $stdoutPath = sys_get_temp_dir() . '/qc-smoke-' . $label . '.out';
    $stderrPath = sys_get_temp_dir() . '/qc-smoke-' . $label . '.err';
    $stdinPath = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';

    $process = proc_open(
        $command,
        [0 => ['file', $stdinPath, 'r'], 1 => ['file', $stdoutPath, 'w'], 2 => ['file', $stderrPath, 'w']],
        $pipes,
        $cwd,
        $env
    );

    if (!is_resource($process)) {
        return [1, '', 'could not start: ' . (is_array($command) ? implode(' ', $command) : $command)];
    }

    $deadline = microtime(true) + $timeout;
    $streamed = 0;
    $exitCode = -1;
    $timedOut = false;

    while (true) {
        $status = proc_get_status($process);
        if ($status['running'] === false) {
            $exitCode = $status['exitcode'];
            break;
        }

        if (microtime(true) >= $deadline) {
            $timedOut = true;
            $pid = (int) proc_get_status($process)['pid'];
            // Kill the tree, not just the child. On Windows the composer call goes
            // through cmd.exe -> composer.bat -> composer.phar, and terminating
            // cmd.exe alone leaves the php process running: an orphan that keeps
            // the temp project locked and has to be hunted down by hand.
            if (PHP_OS_FAMILY === 'Windows' && $pid > 0) {
                @exec('taskkill /F /T /PID ' . $pid . ' 2>&1');
            }
            proc_terminate($process, 9);
            break;
        }

        // Show what the child says as it says it, so a stall is diagnosable from
        // the console instead of only after the deadline kills it.
        if ($debug) {
            clearstatcache(true, $stdoutPath);
            $size = (int) @filesize($stdoutPath);
            if ($size > $streamed) {
                $handle = @fopen($stdoutPath, 'rb');
                if ($handle !== false) {
                    fseek($handle, $streamed);
                    echo (string) fread($handle, $size - $streamed);
                    fclose($handle);
                }
                $streamed = $size;
            }
        }

        usleep(100000);
    }

    proc_close($process);

    $stdout = (string) @file_get_contents($stdoutPath);
    $stderr = (string) @file_get_contents($stderrPath);
    @unlink($stdoutPath);
    @unlink($stderrPath);

    if ($timedOut) {
        return [
            124,
            $stdout,
            $stderr . PHP_EOL . '[smoke] killed `' . $command . '` after ' . $timeout
                . 's without finishing; last output:' . PHP_EOL . trim(substr($stdout . $stderr, -400)),
        ];
    }

    return [$exitCode, $stdout, $stderr];
};

$composer = static fn (string $arguments): string => $composerCommand . ' ' . $arguments;

mkdir($distDir, 0777, true);
mkdir($projectDir, 0777, true);

register_shutdown_function(static fn () => $cleanup($workspace));

echo PHP_EOL . 'Smoke test: distributed artifact' . PHP_EOL . PHP_EOL;

// ---------------------------------------------------------------- archive ---
echo '1. Building the distribution archive' . PHP_EOL;
[$code, $stdout, $stderr] = $run($composer('archive --format=zip --dir=' . escapeshellarg($distDir)), $root);

if ($code !== 0) {
    $fail('composer archive failed: ' . trim($stderr) . trim($stdout));
    echo PHP_EOL . 'Smoke test FAILED' . PHP_EOL;
    exit(1);
}

$archives = glob($distDir . '/*.zip') ?: [];
if ($archives === []) {
    $fail('composer archive produced no zip');
    echo PHP_EOL . 'Smoke test FAILED' . PHP_EOL;
    exit(1);
}

$archive = $archives[0];
$say(basename($archive) . ' (' . round(filesize($archive) / 1024) . ' KB)');

$zip = new ZipArchive();
if ($zip->open($archive) !== true) {
    $fail('cannot open the archive');
    echo PHP_EOL . 'Smoke test FAILED' . PHP_EOL;
    exit(1);
}

$entries = [];
for ($i = 0; $i < $zip->numFiles; $i++) {
    $entries[] = $zip->getNameIndex($i);
}
$zip->close();

echo PHP_EOL . '2. Archive contents' . PHP_EOL;

$required = ['composer.json', 'LICENSE', 'README.md', 'bin/quality-check', 'config/quality-checker.php'];
foreach ($required as $needle) {
    $found = false;
    foreach ($entries as $entry) {
        if (str_ends_with($entry, '/' . $needle) || str_contains($entry, $needle)) {
            $found = true;
            break;
        }
    }
    $found ? $say('contains ' . $needle) : $fail('archive is missing ' . $needle);
}

$forbidden = [
    'vendor/' => 'development dependencies',
    'tests/' => 'the test suite',
    '.github/' => 'CI workflows',
    'tools/' => 'the smoke harness',
    'phpunit.xml.dist' => 'dev config',
    'phpstan-baseline.neon' => 'dev config',
    '.phpunit.result.cache' => 'a local test run cache',
    'CHANGELOG.md' => 'project documentation',
];
foreach ($forbidden as $needle => $label) {
    $found = false;
    foreach ($entries as $entry) {
        if (str_contains($entry, $needle)) {
            $found = true;
            break;
        }
    }
    $found ? $fail('archive ships ' . $label . ' (' . $needle . ')') : $say('excludes ' . $label);
}

// ---------------------------------------------------------------- install ---
echo PHP_EOL . '3. Installing into a throwaway project' . PHP_EOL;

// An artifact repository needs a version in composer.json, and this package
// deliberately declares none: for a Packagist release the tag supplies it, and a
// hardcoded `version` field would override the tag. The archive therefore cannot
// be installed as an artifact as-is. So: extract it, stamp a version, re-zip
// under the name Packagist gives a release. Installing that keeps the test
// honest about the two things that matter — the bytes under test came from
// `composer archive`, and the install is a real dist install, which is what
// creates the vendor/bin proxy (a path repository does not).
//
// The stamped version is 9.9.9, not 0.0.0: 0.0.0 is PackageVersion::FALLBACK, the
// value a report shows when it could not resolve an installed version, so a
// fixture stamped 0.0.0 cannot tell "resolved the real version" from "gave up".
// 9.9.9 is not a version this package will ever release.
$stagedVersion = '9.9.9';
$packageDir = $workspace . '/package';
mkdir($packageDir, 0777, true);

$zip = new ZipArchive();
if ($zip->open($archive) !== true) {
    $fail('cannot reopen the archive for extraction');
    echo PHP_EOL . 'Smoke test FAILED' . PHP_EOL;
    exit(1);
}
$zip->extractTo($packageDir);
$zip->close();

$manifestPath = $packageDir . '/composer.json';
$manifest = json_decode((string) file_get_contents($manifestPath), true);
if (!is_array($manifest)) {
    $fail('composer.json in the archive is not valid JSON');
    echo PHP_EOL . 'Smoke test FAILED' . PHP_EOL;
    exit(1);
}
if (isset($manifest['version'])) {
    $fail('composer.json declares a version field; for a Packagist release the tag must supply it');
}
$manifest['version'] = $stagedVersion;
file_put_contents($manifestPath, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

unlink($archive);
$staged = $distDir . '/rampart-quality-checker-' . $stagedVersion . '.zip';
$zip = new ZipArchive();
if ($zip->open($staged, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    $fail('cannot build the staged artifact');
    echo PHP_EOL . 'Smoke test FAILED' . PHP_EOL;
    exit(1);
}
$zip->addEmptyDir('rampart-quality-checker');
// RecursiveDirectoryIterator hands back plain SplFileInfo, which has no
// getRelativePathname(); derive the path inside the package from its own.
$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($packageDir, FilesystemIterator::SKIP_DOTS)
);
$prefixLength = strlen($packageDir) + 1;
foreach ($iterator as $file) {
    if ($file->isFile()) {
        $zip->addFile($file->getPathname(), 'rampart-quality-checker/' . str_replace('\\', '/', substr($file->getPathname(), $prefixLength)));
    }
}
$zip->close();
$say('staged a versioned artifact from the archive bytes');

file_put_contents(
    $projectDir . '/composer.json',
    json_encode([
        'name' => 'smoke/consumer',
        'require' => ['rampart/quality-checker' => $stagedVersion],
        'repositories' => [['type' => 'artifact', 'url' => $distDir]],
        'config' => ['audit' => ['block-insecure' => false]],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
);

[$code, $stdout, $stderr] = $run($composer('install --no-interaction --no-progress'), $projectDir);

if ($code !== 0) {
    $tail = trim($stdout . PHP_EOL . $stderr);
    $fail('composer install failed (exit ' . $code . '):' . PHP_EOL . '    ' . str_replace(PHP_EOL, PHP_EOL . '    ', $tail));
    echo PHP_EOL . 'Smoke test FAILED' . PHP_EOL;
    exit(1);
}

$say('composer install completed');

// ------------------------------------------------------------------- scan ---
echo PHP_EOL . '4. Running the installed binary' . PHP_EOL;

mkdir($projectDir . '/app/Http/Controllers', 0777, true);
file_put_contents(
    $projectDir . '/app/Http/Controllers/SmokeController.php',
    "<?php\nnamespace App\\Http;\nclass SmokeController\n{\n    public function destroy(\$id)\n    {\n        \\Order::find(\$id)->delete();\n    }\n}\n"
);

// Composer generates the proxy in platform-specific form — a shell script, a
// .bat, or a PHP file depending on host and `bin-compat`. What must exist is the
// proxy; what must run is our own script, so the scan drives it directly rather
// than depending on the host's proxy flavour.
$proxies = glob($projectDir . '/vendor/bin/quality-check*') ?: [];
$proxies === []
    ? $fail('composer did not create a vendor/bin proxy for the package binary')
    : $say('bin proxy: ' . implode(', ', array_map('basename', $proxies)));

// The bug this replaces: the installed script looked for
// <package>/vendor/autoload.php, which does not exist once hoisted.
is_file($projectDir . '/vendor/autoload.php')
    ? $say('project autoloader present (dependencies hoisted)')
    : $fail('project autoloader missing');

$script = $projectDir . '/vendor/rampart/quality-checker/bin/quality-check';
is_file($script)
    ? $say('package script installed')
    : $fail('package script missing at vendor/rampart/quality-checker/bin/quality-check');

[$code, $stdout, $stderr] = $run(
    [PHP_BINARY, $script, $projectDir, '--only=custom', '--tier=security', '--fail-on=none', '--no-cache'],
    $projectDir
);

if (str_contains($stdout . $stderr, 'autoloader')) {
    $fail('the installed binary could not locate an autoloader: ' . trim($stdout . $stderr));
} elseif (trim($stdout) === '') {
    $fail('the installed binary produced no output');
} else {
    $say('binary started (autoloader resolved from the project root)');
}

// The version stamped into the staged artifact has to survive the whole trip:
// composer.json → Composer → InstalledVersions → the report header. That is the
// assertion, and it is what regressed when the standalone runner stamped every
// report with CheckContext's 0.0.0 default.
preg_match('/Laravel Quality Checker (\S+)/', $stdout, $version);
$version = $version[1] ?? '';
if ($version !== 'v' . $stagedVersion) {
    $fail('report header reads "' . $version . '", expected "v' . $stagedVersion . '" from the installed version');
} else {
    $say('report header version: ' . $version);
}

preg_match('/Custom analyzers found (\d+) issue/', $stdout, $found);
$issueCount = (int) ($found[1] ?? 0);
if ($issueCount === 0) {
    $fail('the known-bad controller produced no findings — analyzers did not run');
} else {
    $say('found ' . $issueCount . ' issue(s) in the planted controller');
}

// ------------------------------------------------------------------ result ---
echo PHP_EOL;

if ($failures !== []) {
    echo 'Smoke test FAILED — ' . count($failures) . ' of ' . $checks . ' checks:' . PHP_EOL;
    foreach ($failures as $failure) {
        echo '  - ' . $failure . PHP_EOL;
    }
    exit(1);
}

echo 'Smoke test passed — ' . $checks . ' checks.' . PHP_EOL;
exit(0);
