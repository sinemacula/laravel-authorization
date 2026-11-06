<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Support\DeclaredAbilities;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\RecordingPermissionProvider;
use Tests\Feature\Stubs\StubPermissionProvider;
use Tests\TestCase;

/**
 * Feature tests for `DeclaredAbilities`, the exact names the package answers
 * through Laravel's Gate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DeclaredAbilities::class)]
final class DeclaredAbilitiesTest extends TestCase
{
    /**
     * Reset the recording provider before each test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        RecordingPermissionProvider::$reads = 0;
    }

    /**
     * Every case of a configured enum, every permission of a configured
     * provider, whatever its guard, and the package's own permissions are held.
     *
     * @return void
     */
    public function testHoldsEveryDeclaredPermission(): void
    {
        $abilities = $this->abilities([PermissionEnum::class], [StubPermissionProvider::class]);

        foreach (['posts:create', 'posts:delete', 'media:upload', 'media:delete', 'billing:view', PackagePermissions::GUARDRAILS_MANAGE] as $name) {
            self::assertTrue($abilities->holds($name), $name);
        }
    }

    /**
     * Only an exact name is held: a pattern covering a declared name, a near
     * miss of one, a permission row that exists only in the database, and, with
     * nothing configured, every application name are not.
     *
     * @return void
     */
    public function testHoldsOnlyAnExactDeclaredName(): void
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'reports:archive', 'guard' => 'web']);

        $abilities = $this->abilities([PermissionEnum::class], []);

        foreach (['posts:*', '*', 'posts?create', 'Posts:Create', 'posts:create ', 'posts', '', 'reports:archive', 'media:upload'] as $name) {
            self::assertFalse($abilities->holds($name), $name);
        }

        $nothing = $this->abilities([], []);

        self::assertFalse($nothing->holds('posts:create'));
        self::assertTrue($nothing->holds(PackagePermissions::GUARDRAILS_MANAGE));
    }

    /**
     * The catalogue is read the first time an ability is asked about and once
     * only for the instance, however many are asked about; building the
     * instance reads nothing.
     *
     * @return void
     */
    public function testReadsTheCatalogueOncePerInstance(): void
    {
        $abilities = $this->abilities([], [RecordingPermissionProvider::class]);

        self::assertSame(0, RecordingPermissionProvider::$reads);

        self::assertTrue($abilities->holds('reports:export'));
        self::assertFalse($abilities->holds('reports:import'));
        self::assertTrue($abilities->holds('reports:export'));

        self::assertSame(1, RecordingPermissionProvider::$reads);
    }

    /**
     * The instance the Gate registrar binds is one per request or job: it is
     * shared until the scoped instances are forgotten, and then built and read
     * afresh, so a catalogue changed between jobs is seen.
     *
     * @return void
     */
    public function testTheBoundInstanceIsScoped(): void
    {
        config(['authorization.permission_providers' => [RecordingPermissionProvider::class]]);

        $first = DeclaredAbilities::instance();

        self::assertNotNull($first);
        self::assertSame($first, DeclaredAbilities::instance());
        self::assertTrue($first->holds('reports:export'));

        $this->app?->forgetScopedInstances();
        config(['authorization.permission_providers' => []]);

        $second = DeclaredAbilities::instance();

        self::assertNotSame($first, $second);
        self::assertFalse($second->holds('reports:export'));
        self::assertSame(1, RecordingPermissionProvider::$reads);
    }

    /**
     * Build a new set of declared abilities over the given enums and providers.
     *
     * @param  list<class-string>  $enums
     * @param  list<class-string>  $providers
     * @return \SineMacula\Laravel\Authorization\Support\DeclaredAbilities
     */
    private function abilities(array $enums, array $providers): DeclaredAbilities
    {
        config([
            'authorization.permission_enums'     => $enums,
            'authorization.permission_providers' => $providers,
        ]);

        /** @var \SineMacula\Laravel\Authorization\Support\PermissionCatalogue $catalogue */
        $catalogue = $this->app?->make(PermissionCatalogue::class);

        return new DeclaredAbilities($catalogue);
    }
}
