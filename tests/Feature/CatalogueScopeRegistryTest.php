<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authorization\Support\CatalogueScopeRegistry;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\SessionScopes;
use Tests\Feature\Stubs\ConfigurablePermissionProvider;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\RecordingPermissionProvider;
use Tests\TestCase;

/**
 * Feature tests for `CatalogueScopeRegistry`, the scope registry backed by the
 * permission catalogue and the scope map.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(CatalogueScopeRegistry::class)]
final class CatalogueScopeRegistryTest extends TestCase
{
    /**
     * Declare the stub enum's permissions and the recording provider's, and
     * reset its count of reads.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        RecordingPermissionProvider::$reads          = 0;
        ConfigurablePermissionProvider::$permissions = [];

        $this->config()->set('authorization.permission_enums', [PermissionEnum::class]);
        $this->config()->set('authorization.permission_providers', [RecordingPermissionProvider::class]);
    }

    /**
     * A scope the map names is valid, and so is every other scope that names a
     * declared permission, the package's own included, or a pattern covering
     * one; any other scope is not.
     *
     * @return void
     */
    public function testAValidScopeIsMappedOrNamesADeclaredPermission(): void
    {
        $registry = $this->registry(['editor' => ['posts:*']]);

        foreach (['editor', 'posts:create', 'posts:*', 'reports:export', '*', PackagePermissions::GUARDRAIL_MANAGE, 'authorization:*'] as $scope) {
            self::assertTrue($registry->isValid($scope), $scope);
        }

        foreach (['reader', 'posts:read', 'users:*', '', 'posts:create '] as $scope) {
            self::assertFalse($registry->isValid($scope), $scope);
        }
    }

    /**
     * A scope is matched against the declared names as a pattern with no
     * escapes, and by equality, as a cap matches an action.
     *
     * @return void
     */
    public function testAScopeIsMatchedAsAPatternWithNoEscapes(): void
    {
        $registry = $this->registry([]);

        self::assertTrue($registry->isValid('posts:creat?'));
        self::assertTrue($registry->isValid('posts:[cd]*'));
        self::assertFalse($registry->isValid('posts\:create'));
    }

    /**
     * The scopes are those the map names, in its order, then each declared
     * permission the map does not name, the package's own first, once even when
     * it is declared for two guards.
     *
     * @return void
     */
    public function testTheScopesAreTheMappedThenTheDeclared(): void
    {
        ConfigurablePermissionProvider::$permissions = [new PermissionDefinition(name: 'posts:delete', guard: 'api')];

        $this->config()->set('authorization.permission_providers', [RecordingPermissionProvider::class, ConfigurablePermissionProvider::class]);

        $registry = $this->registry(['editor' => ['posts:*'], 'posts:create']);

        self::assertSame(['editor', 'posts:create', ...self::packagePermissions(), 'posts:delete', 'reports:export'], $registry->scopes());
    }

    /**
     * The catalogue is read the first time a scope is asked about and kept, and
     * not at all for a scope the map names.
     *
     * @return void
     */
    public function testTheCatalogueIsReadOnceAndOnlyWhenNeeded(): void
    {
        $registry = $this->registry(['editor' => ['posts:*']]);

        self::assertTrue($registry->isValid('editor'));
        self::assertSame(0, RecordingPermissionProvider::$reads);

        $registry->isValid('posts:create');
        $registry->isValid('posts:delete');
        $registry->scopes();

        self::assertSame(1, RecordingPermissionProvider::$reads);
    }

    /**
     * The registry is optional: the package binds none, and an application
     * binds this one, which the container builds with the configured scope map.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testTheContainerBuildsItWithTheConfiguredMap(): void
    {
        $app = $this->app ?? throw new \LogicException('The application has not been created.');

        self::assertFalse($app->bound(ScopeRegistry::class));

        $this->config()->set('authorization.session.scopes', ['editor' => ['posts:*']]);
        $app->forgetScopedInstances();
        $app->bind(ScopeRegistry::class, CatalogueScopeRegistry::class);

        $registry = $app->make(ScopeRegistry::class);

        self::assertInstanceOf(CatalogueScopeRegistry::class, $registry);
        self::assertTrue($registry->isValid('editor'));
        self::assertSame('editor', $registry->scopes()[0]);
    }

    /**
     * Return a registry over the declared permissions and the scope map given.
     *
     * @param  array<array-key, mixed>  $map
     * @return \SineMacula\Laravel\Authorization\Support\CatalogueScopeRegistry
     */
    private function registry(array $map): CatalogueScopeRegistry
    {
        /** @var \SineMacula\Laravel\Authorization\Support\PermissionCatalogue $catalogue */
        $catalogue = $this->app?->make(PermissionCatalogue::class);

        return new CatalogueScopeRegistry($catalogue, SessionScopes::fromConfig($map));
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

    /**
     * Return the name of every permission the package declares, in its order.
     *
     * @return list<string>
     */
    private static function packagePermissions(): array
    {
        return \array_map(static fn (PermissionDefinition $definition): string => $definition->name, (new PackagePermissions)->permissions());
    }
}
