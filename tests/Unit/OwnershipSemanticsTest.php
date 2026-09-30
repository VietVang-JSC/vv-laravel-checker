<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspOwnershipAnalyzer;
use Rampart\QualityChecker\Semantic\OwnershipDecision;
use Rampart\QualityChecker\Semantic\OwnershipShadow;

/**
 * v0.6.1 ownership corpus (shadow mode). Auth alone is never
 * ownership; only the bounded evidence shapes prove PROTECTED.
 */
final class OwnershipSemanticsTest extends TestCase
{
    /** @var list<string> */
    private array $dirs = [];

    protected function tearDown(): void
    {
        OwnershipShadow::reset();
        foreach ($this->dirs as $dir) {
            $items = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($items as $item) {
                $path = $item->getPathname();
                if (is_dir($path)) {
                    @rmdir($path);
                } else {
                    @unlink($path);
                }
            }
            @rmdir($dir);
        }
        $this->dirs = [];
        parent::tearDown();
    }

    /**
     * @param array<string, string> $files relPath => content
     * @return list<string> absolute paths
     */
    private function project(array $files): array
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-sem-own-' . uniqid('', true);
        @mkdir($dir, 0777, true);
        $this->dirs[] = $dir;
        $paths = [];
        foreach ($files as $rel => $content) {
            $path = $dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
            @mkdir(dirname($path), 0777, true);
            file_put_contents($path, $content);
            $paths[] = $path;
        }

        return $paths;
    }

    private function controller(string $body): string
    {
        return "<?php\nnamespace App\\Http\\Controllers;\n"
            . "use App\\Models\\Link;\nuse Illuminate\\Http\\Request;\nuse Illuminate\\Support\\Facades\\Auth;\n"
            . "class LinkController extends Controller {\n"
            . "    public function destroy(Request \$request) {\n"
            . $body . "\n"
            . "    }\n"
            . "}\n";
    }

    private function routes(string $middleware): string
    {
        return "<?php\nuse Illuminate\\Support\\Facades\\Route;\n"
            . "use App\\Http\\Controllers\\LinkController;\n"
            . "Route::delete('/links/{id}', [LinkController::class, 'destroy'])->middleware([{$middleware}]);\n";
    }

    /**
     * @param array<string, string> $files
     * @return list<OwnershipDecision>
     */
    private function decisions(array $files): array
    {
        OwnershipShadow::reset();
        $paths = $this->project($files);
        (new OwaspOwnershipAnalyzer())->analyze($paths);

        return OwnershipShadow::all();
    }

    public function testRelationshipScopedIsProtected(): void
    {
        $decisions = $this->decisions([
            'app/Http/Controllers/LinkController.php' => $this->controller(
                "        \$user = Auth::user();\n"
                . "        \$user->links()->where('id', \$request->id)->delete();\n"
                . "        return redirect('/links');\n"
            ),
            'routes/web.php' => $this->routes("'auth'"),
        ]);
        self::assertCount(1, $decisions);
        self::assertSame(OwnershipDecision::PROTECTED, $decisions[0]->status);
        self::assertSame('relationship-scoped', $decisions[0]->ownershipEvidence[0]['mechanism']);
    }

    public function testOwnerWhereIsProtected(): void
    {
        $decisions = $this->decisions([
            'app/Http/Controllers/LinkController.php' => $this->controller(
                "        Link::where('user_id', Auth::id())->where('id', \$request->id)->delete();\n"
                . "        return redirect('/links');\n"
            ),
            'routes/web.php' => $this->routes("'auth'"),
        ]);
        self::assertCount(1, $decisions);
        self::assertSame(OwnershipDecision::PROTECTED, $decisions[0]->status);
        self::assertSame('owner-where', $decisions[0]->ownershipEvidence[0]['mechanism']);
    }

    public function testOwnerCompareDenyIsProtected(): void
    {
        $decisions = $this->decisions([
            'app/Http/Controllers/LinkController.php' => $this->controller(
                "        \$link = Link::find(\$request->id);\n"
                . "        if (\$link->user_id != Auth::id()) {\n"
                . "            abort(403);\n"
                . "        }\n"
                . "        \$link->delete();\n"
                . "        return redirect('/links');\n"
            ),
            'routes/web.php' => $this->routes("'auth'"),
        ]);
        self::assertCount(1, $decisions);
        self::assertSame(OwnershipDecision::PROTECTED, $decisions[0]->status);
        self::assertSame('owner-compare-deny', $decisions[0]->ownershipEvidence[0]['mechanism']);
    }

    public function testAuthorizeCallIsProtected(): void
    {
        $decisions = $this->decisions([
            'app/Http/Controllers/LinkController.php' => $this->controller(
                "        \$link = Link::find(\$request->id);\n"
                . "        \$this->authorize('delete', \$link);\n"
                . "        \$link->delete();\n"
                . "        return redirect('/links');\n"
            ),
            'routes/web.php' => $this->routes("'auth'"),
        ]);
        self::assertCount(1, $decisions);
        self::assertSame(OwnershipDecision::PROTECTED, $decisions[0]->status);
        self::assertSame('policy-gate', $decisions[0]->authorizationEvidence[0]['mechanism']);
    }

    public function testCanMiddlewareIsProtected(): void
    {
        $decisions = $this->decisions([
            'app/Http/Controllers/LinkController.php' => $this->controller(
                "        Link::where('id', \$request->id)->delete();\n"
                . "        return redirect('/links');\n"
            ),
            'routes/web.php' => $this->routes("'auth', 'can:delete,link'"),
        ]);
        self::assertCount(1, $decisions);
        self::assertSame(OwnershipDecision::PROTECTED, $decisions[0]->status);
        self::assertSame('can-middleware', $decisions[0]->authorizationEvidence[0]['mechanism']);
    }

    public function testAuthOnlyDeleteIsReview(): void
    {
        // deleteLink shape: request id → model lookup → delete, auth but
        // no ownership proof.
        $decisions = $this->decisions([
            'app/Http/Controllers/LinkController.php' => $this->controller(
                "        \$linkId = \$request->id;\n"
                . "        Link::where('id', \$linkId)->delete();\n"
                . "        return redirect('/links');\n"
            ),
            'routes/web.php' => $this->routes("'auth'"),
        ]);
        self::assertCount(1, $decisions);
        self::assertSame(OwnershipDecision::REVIEW, $decisions[0]->status);
        self::assertSame('request-var', $decisions[0]->identifier['kind']);
        self::assertSame('model-query', $decisions[0]->lookup['kind']);
        self::assertSame([], $decisions[0]->ownershipEvidence);
    }

    public function testPublicDeleteIsExposed(): void
    {
        $decisions = $this->decisions([
            'app/Http/Controllers/LinkController.php' => $this->controller(
                "        Link::where('id', \$request->id)->delete();\n"
                . "        return redirect('/links');\n"
            ),
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n"
                . "use App\\Http\\Controllers\\LinkController;\n"
                . "Route::delete('/links/{id}', [LinkController::class, 'destroy']);\n",
        ]);
        self::assertCount(1, $decisions);
        self::assertSame(OwnershipDecision::EXPOSED, $decisions[0]->status);
    }

    public function testCustomMiddlewareStaysReview(): void
    {
        // Ownership-shaped custom middleware is NOT proven in v0.6.1.
        $decisions = $this->decisions([
            'app/Http/Controllers/LinkController.php' => $this->controller(
                "        \$linkId = \$request->id;\n"
                . "        Link::where('id', \$linkId)->delete();\n"
                . "        return redirect('/links');\n"
            ),
            'routes/web.php' => $this->routes("'auth', 'link-id'"),
        ]);
        self::assertCount(1, $decisions);
        self::assertSame(OwnershipDecision::REVIEW, $decisions[0]->status);
    }

    public function testAuthorizeAfterSinkStaysReview(): void
    {
        // A check positioned after the write proves nothing.
        $decisions = $this->decisions([
            'app/Http/Controllers/LinkController.php' => $this->controller(
                "        \$link = Link::find(\$request->id);\n"
                . "        \$link->delete();\n"
                . "        \$this->authorize('delete', \$link);\n"
                . "        return redirect('/links');\n"
            ),
            'routes/web.php' => $this->routes("'auth'"),
        ]);
        self::assertCount(1, $decisions);
        self::assertSame(OwnershipDecision::REVIEW, $decisions[0]->status);
    }

    public function testTwoStepLookupTracksIdentifier(): void
    {
        // $group = Group::find($id); ... $group->delete() — the id
        // reaches the sink through the lookup assignment.
        $decisions = $this->decisions([
            'app/Http/Controllers/LinkController.php' => $this->controller(
                "        \$link = Link::find(\$request->id);\n"
                . "        \$link->delete();\n"
                . "        return redirect('/links');\n"
            ),
            'routes/web.php' => $this->routes("'auth'"),
        ]);
        self::assertCount(1, $decisions);
        self::assertSame(OwnershipDecision::REVIEW, $decisions[0]->status);
        self::assertNotNull($decisions[0]->identifier);
    }

    public function testNoSensitiveOpEmitsNothing(): void
    {
        $decisions = $this->decisions([
            'app/Http/Controllers/LinkController.php' => $this->controller(
                "        \$link = Link::find(\$request->id);\n"
                . "        return view('links.show', ['link' => \$link]);\n"
            ),
            'routes/web.php' => $this->routes("'auth'"),
        ]);
        self::assertCount(0, $decisions);
    }
}
