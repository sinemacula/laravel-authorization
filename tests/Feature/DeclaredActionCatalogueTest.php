<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use Tests\Concerns\RefusesThePackage;
use Tests\Feature\Stubs\ConfigurablePermissionProvider;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\Feature\Stubs\LenientNamePermission;
use Tests\Feature\Stubs\RecordingPermissionProvider;
use Tests\TestCase;

/**
 * Feature tests for `DeclaredActionCatalogue`, the actions the configured
 * permission enums and providers declare, the package's own left out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DeclaredActionCatalogue::class)]
final class DeclaredActionCatalogueTest extends TestCase
{
    use RefusesThePackage;

    /**
     * Reset the configurable and recording providers before each test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        ConfigurablePermissionProvider::$permissions = [];
        RecordingPermissionProvider::$reads          = 0;
    }

    /**
     * A pattern covers the catalogue when it names a declared permission or
     * matches one, from an enum or a provider, whatever its guard.
     *
     * @return void
     */
    public function testCoversADeclaredPermissionByNameOrPattern(): void
    {
        ConfigurablePermissionProvider::$permissions = [new PermissionDefinition(name: 'reports:export', guard: 'api')];

        $catalogue = $this->catalogue([CataloguePermission::class], [ConfigurablePermissionProvider::class]);

        foreach (['posts:create', 'posts.publish', 'posts:*', '*', 'posts?create', 'reports:export', 'reports:*'] as $pattern) {
            self::assertTrue($catalogue->covers($pattern), $pattern);
        }

        foreach (['posts:delete', 'posts:create:*', 'comments:*', 'POSTS:CREATE', ''] as $pattern) {
            self::assertFalse($catalogue->covers($pattern), $pattern);
        }
    }

    /**
     * With nothing configured, no pattern covers the catalogue, not even `*`:
     * the package's own permissions are not the application's, and are left
     * out.
     *
     * @return void
     */
    public function testCoversNothingWhenNothingIsConfigured(): void
    {
        $catalogue = $this->catalogue([], []);

        self::assertFalse($catalogue->covers('*'));
        self::assertFalse($catalogue->covers('authorization:guardrail.manage'));
        self::assertFalse($catalogue->covers('posts:create'));
    }

    /**
     * The package's own permissions are left out beside the application's, also
     * when the application declares one of them itself.
     *
     * @return void
     */
    public function testLeavesOutThePackagesOwnPermissions(): void
    {
        ConfigurablePermissionProvider::$permissions = [
            new PermissionDefinition(name: 'authorization:guardrail.manage', description: 'Set and remove guardrails from above the scope they cap.', category: 'authorization'),
        ];

        $catalogue = $this->catalogue([CataloguePermission::class], [ConfigurablePermissionProvider::class]);

        self::assertTrue($catalogue->covers('*'));
        self::assertTrue($catalogue->covers('posts:create'));
        self::assertFalse($catalogue->covers('authorization:guardrail.manage'));
        self::assertFalse($catalogue->covers('authorization:*'));
    }

    /**
     * A pattern that is a declared name covers it even when `fnmatch` would
     * read the name as a pattern, and a backslash is matched literally.
     *
     * @return void
     */
    public function testCoversADeclaredNameItselfAndMatchesBackslashesLiterally(): void
    {
        $this->config()->set('authorization.models.permission', LenientNamePermission::class);

        ConfigurablePermissionProvider::$permissions = [new PermissionDefinition(name: 'posts[draft]'), new PermissionDefinition(name: 'files\read')];

        $catalogue = $this->catalogue([], [ConfigurablePermissionProvider::class]);

        self::assertTrue($catalogue->covers('posts[draft]'));
        self::assertTrue($catalogue->covers('files\*'));
        self::assertFalse($catalogue->covers('postsd'));
        self::assertFalse($catalogue->covers('files\\\read'));
    }

    /**
     * The declared names are read once, the first time a pattern is asked
     * about, and kept for the catalogue's lifetime.
     *
     * @return void
     */
    public function testReadsTheDeclaredNamesOnce(): void
    {
        $catalogue = $this->catalogue([], [RecordingPermissionProvider::class]);

        self::assertSame(0, RecordingPermissionProvider::$reads);
        self::assertTrue($catalogue->covers('reports:export'));
        self::assertFalse($catalogue->covers('reports:import'));
        self::assertSame(1, RecordingPermissionProvider::$reads);
    }

    /**
     * While the package is pending, as the boot's own validation asks, a
     * pattern is matched; once the package refuses, asking refuses by the
     * catalogue's own guard, with the names read before or without, before any
     * provider declares a permission again.
     *
     * @return void
     */
    public function testCoveringRefusesWhileThePackageRefuses(): void
    {
        $catalogue = $this->catalogue([], [RecordingPermissionProvider::class]);
        $state     = PackageState::of($this->container());

        $state?->pending();

        self::assertTrue($catalogue->covers('reports:export'));

        $this->refuseThePackage();

        $this->assertEachRefused([
            'covers'                      => static fn () => $catalogue->covers('reports:export'),
            'covers on a fresh catalogue' => fn () => $this->catalogue([], [RecordingPermissionProvider::class])->covers('reports:export'),
        ]);

        self::assertSame(1, RecordingPermissionProvider::$reads);
    }

    /**
     * Configure the enums and providers, and build the catalogue from the
     * container.
     *
     * @param  list<class-string>  $enums
     * @param  list<class-string>  $providers
     * @return \SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue
     */
    private function catalogue(array $enums, array $providers): DeclaredActionCatalogue
    {
        $this->config()->set('authorization.permission_enums', $enums);
        $this->config()->set('authorization.permission_providers', $providers);

        /** @var \SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue */
        return $this->app?->make(DeclaredActionCatalogue::class);
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        /** @var \Illuminate\Config\Repository */
        return $this->app?->make(ConfigRepository::class);
    }
}
