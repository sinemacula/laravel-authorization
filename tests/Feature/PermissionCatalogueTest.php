<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\PermissionMetadataReader;
use Tests\Feature\Stubs\ConfigurablePermissionProvider;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\Feature\Stubs\Enums\IntBackedPermissionEnum;
use Tests\Feature\Stubs\Enums\InvalidNamePermission;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\InjectedPermissionProvider;
use Tests\Feature\Stubs\StubPermissionProvider;
use Tests\TestCase;

/**
 * Feature tests for `PermissionCatalogue`, the permissions the package, the
 * configured enums and the configured providers declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PermissionCatalogue::class)]
#[CoversClass(PermissionMetadataReader::class)]
#[CoversClass(PermissionDefinition::class)]
#[CoversClass(InvalidPermissionCatalogueException::class)]
final class PermissionCatalogueTest extends TestCase
{
    /**
     * Reset the configurable provider before each test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        ConfigurablePermissionProvider::$permissions = [];
    }

    /**
     * The package's own permissions come first, then the enums' cases, one
     * definition per guard, then each provider's definitions, in the order
     * declared.
     *
     * @return void
     */
    public function testReadsTheEnumsThenTheProvidersInOrder(): void
    {
        $this->configure([CataloguePermission::class], [StubPermissionProvider::class]);

        self::assertEquals(
            [
                ...(new PackagePermissions)->permissions(),
                new PermissionDefinition(name: 'posts:create', description: 'Create posts', category: 'Posts'),
                new PermissionDefinition(name: 'posts.publish', description: 'Publish posts', category: 'Posts', guard: 'web'),
                new PermissionDefinition(name: 'posts.publish', description: 'Publish posts', category: 'Posts', guard: 'api'),
                new PermissionDefinition('posts:archive'),
                new PermissionDefinition(name: 'media:upload', description: 'Upload media', category: 'Media', guard: 'web'),
                new PermissionDefinition(name: 'media:delete', description: 'Delete media', category: 'Media', guard: 'web'),
                new PermissionDefinition('billing:view'),
            ],
            $this->catalogue()->definitions(),
        );
    }

    /**
     * A provider is resolved through the container, so its constructor
     * dependencies are injected.
     *
     * @return void
     */
    public function testResolvesEachProviderThroughTheContainer(): void
    {
        $definition = new PermissionDefinition(name: 'module:view', description: 'View the module', category: 'Module');

        $this->app?->instance(PermissionDefinition::class, $definition);

        $this->configure([], [InjectedPermissionProvider::class]);

        self::assertSame($definition, $this->catalogue()->definitions()[1]);
        self::assertCount(2, $this->catalogue()->definitions());
    }

    /**
     * With nothing configured the catalogue holds the package's own permissions
     * alone: the right to manage guardrails, guard-agnostic, filed under the
     * package's category.
     *
     * @return void
     */
    public function testHoldsThePackagesPermissionsWithNothingConfigured(): void
    {
        $this->configure([], []);

        self::assertEquals([
            new PermissionDefinition(
                'authorization:guardrails:manage',
                'Set and remove guardrails from above the scope they cap.',
                'authorization',
            ),
        ], $this->catalogue()->definitions());
    }

    /**
     * An application declaring a package permission again with the same
     * metadata keeps it once, and with other metadata is refused.
     *
     * @return void
     */
    public function testAPackagePermissionDeclaredAgainKeepsToTheDuplicateRule(): void
    {
        ConfigurablePermissionProvider::$permissions = (new PackagePermissions)->permissions();

        $this->configure([], [ConfigurablePermissionProvider::class]);

        self::assertCount(1, $this->catalogue()->definitions());

        ConfigurablePermissionProvider::$permissions = [new PermissionDefinition(PackagePermissions::GUARDRAILS_MANAGE, 'Mine')];

        $this->expectException(InvalidPermissionCatalogueException::class);

        $this->catalogue()->definitions();
    }

    /**
     * A permission declared twice for the same guard with the same metadata is
     * kept once, where it was first declared.
     *
     * @return void
     */
    public function testKeepsAnAgreeingDuplicateOnce(): void
    {
        ConfigurablePermissionProvider::$permissions = [
            new PermissionDefinition(name: 'posts:create', description: 'Create posts', category: 'Posts'),
            new PermissionDefinition(name: 'posts:create', description: 'Create posts', category: 'Posts', guard: 'web'),
        ];

        $this->configure([CataloguePermission::class], [ConfigurablePermissionProvider::class]);

        $definitions = $this->catalogue()->definitions();

        self::assertCount(6, $definitions);
        self::assertEquals(new PermissionDefinition(name: 'posts:create', description: 'Create posts', category: 'Posts'), $definitions[1]);
        self::assertEquals(new PermissionDefinition(name: 'posts:create', description: 'Create posts', category: 'Posts', guard: 'web'), $definitions[5]);
    }

    /**
     * A permission declared twice for the same guard with a different
     * description or category is refused, naming the second declaration.
     *
     * @return void
     */
    public function testRefusesAConflictingDuplicate(): void
    {
        ConfigurablePermissionProvider::$permissions = [new PermissionDefinition(name: 'posts:create', description: 'Write posts', category: 'Posts')];

        $this->configure([CataloguePermission::class], [ConfigurablePermissionProvider::class]);

        $this->assertRefused(
            ConfigurablePermissionProvider::class,
            '\'posts:create\' is already declared for the same guard with a different description or category.',
        );
    }

    /**
     * A case whose value breaks the name rules is refused, naming the case.
     *
     * @return void
     */
    public function testRefusesAnInvalidEnumName(): void
    {
        $this->configure([InvalidNamePermission::class], []);

        $this->assertRefused(
            InvalidNamePermission::class . '::SPACED',
            '\'reports edit\' is not a valid permission name: allowed characters are letters, digits, \'_\', \'-\', \':\', \'.\' and \'*\', at most 191 of them.',
        );
    }

    /**
     * A provider's definition whose name breaks the name rules is refused,
     * naming the provider.
     *
     * @return void
     */
    public function testRefusesAnInvalidProviderName(): void
    {
        ConfigurablePermissionProvider::$permissions = [new PermissionDefinition('media[upload]')];

        $this->configure([], [ConfigurablePermissionProvider::class]);

        $this->assertRefused(
            ConfigurablePermissionProvider::class,
            '\'media[upload]\' is not a valid permission name: allowed characters are letters, digits, \'_\', \'-\', \':\', \'.\' and \'*\', at most 191 of them.',
        );
    }

    /**
     * A definition whose guard is an empty string is refused.
     *
     * @return void
     */
    public function testRefusesAnEmptyGuard(): void
    {
        ConfigurablePermissionProvider::$permissions = [new PermissionDefinition(name: 'media:upload', guard: '')];

        $this->configure([], [ConfigurablePermissionProvider::class]);

        $this->assertRefused(ConfigurablePermissionProvider::class, 'the guard of \'media:upload\' must be null or a non-empty string.');
    }

    /**
     * A provider returning something other than definitions is refused.
     *
     * @return void
     */
    public function testRefusesAProviderReturningSomethingElse(): void
    {
        ConfigurablePermissionProvider::$permissions = ['media:upload'];

        $this->configure([], [ConfigurablePermissionProvider::class]);

        $this->assertRefused(
            ConfigurablePermissionProvider::class,
            'permissions() must return ' . PermissionDefinition::class . ' instances, got string.',
        );
    }

    /**
     * The configuration is read after boot, so an entry of the configured enums
     * the boot validation would refuse is skipped, whatever it is, and the
     * enums around it are read.
     *
     * @return void
     */
    public function testSkipsAnEnumEntryTheValidationWouldRefuse(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);

        $config->set('authorization.permission_enums', [123, \stdClass::class, IntBackedPermissionEnum::class, ['nested'], null, PermissionEnum::class]);

        self::assertEquals(
            [...(new PackagePermissions)->permissions(), new PermissionDefinition('posts:create'), new PermissionDefinition('posts:delete')],
            $this->catalogue()->definitions(),
        );
    }

    /**
     * Set the configured enums and providers.
     *
     * @param  list<class-string>  $enums
     * @param  list<class-string>  $providers
     * @return void
     */
    private function configure(array $enums, array $providers): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);

        $config->set('authorization.permission_enums', $enums);
        $config->set('authorization.permission_providers', $providers);
    }

    /**
     * Return the catalogue as the container builds it.
     *
     * @return \SineMacula\Laravel\Authorization\Support\PermissionCatalogue
     */
    private function catalogue(): PermissionCatalogue
    {
        /** @var \SineMacula\Laravel\Authorization\Support\PermissionCatalogue */
        return $this->app?->make(PermissionCatalogue::class);
    }

    /**
     * Assert that reading the catalogue is refused with the given source and
     * reason.
     *
     * @param  string  $source
     * @param  string  $reason
     * @return void
     */
    private function assertRefused(string $source, string $reason): void
    {
        try {
            $this->catalogue()->definitions();
            self::fail('InvalidPermissionCatalogueException was not thrown.');
        } catch (InvalidPermissionCatalogueException $exception) {
            self::assertSame($source, $exception->getSource());
            self::assertSame($reason, $exception->getReason());
        }
    }
}
