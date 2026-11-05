<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\CustomPermission;
use Tests\Feature\Stubs\CustomPolicy;
use Tests\Feature\Stubs\CustomRole;
use Tests\TestCase;

/**
 * Feature tests for the boot-time validation of `authorization.models.*`.
 *
 * Each entry must name an existing class that is the shipped model or a
 * subclass of it; anything else is refused with the offending key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ConfigValidator::class)]
#[CoversClass(InvalidAuthorizationConfigException::class)]
final class ConfigValidatorTest extends TestCase
{
    /**
     * The shipped models pass validation.
     *
     * @return void
     */
    public function testShippedModelsPass(): void
    {
        $this->validateWithModels([
            'role'       => Role::class,
            'permission' => Permission::class,
            'policy'     => Policy::class,
        ]);

        $this->expectNotToPerformAssertions();
    }

    /**
     * Subclasses of the shipped models pass validation.
     *
     * @return void
     */
    public function testSubclassesOfShippedModelsPass(): void
    {
        $this->validateWithModels([
            'role'       => CustomRole::class,
            'permission' => CustomPermission::class,
            'policy'     => CustomPolicy::class,
        ]);

        $this->expectNotToPerformAssertions();
    }

    /**
     * A `models` block with keys left out passes: each missing key falls back
     * to the shipped model.
     *
     * @return void
     */
    public function testMissingModelKeysPass(): void
    {
        $this->validateWithModels([]);

        $this->expectNotToPerformAssertions();
    }

    /**
     * A config with no `models` block at all passes.
     *
     * @return void
     */
    public function testAbsentModelsBlockPasses(): void
    {
        $config = $this->authorizationConfig();

        unset($config['models']);

        ConfigValidator::validate($config, $this->app);

        $this->expectNotToPerformAssertions();
    }

    /**
     * A `models` block that is not an array is refused.
     *
     * @return void
     */
    public function testNonArrayModelsBlockIsRejected(): void
    {
        $config           = $this->authorizationConfig();
        $config['models'] = 'role';

        $this->assertRejected(
            fn () => ConfigValidator::validate($config, $this->app),
            'authorization.models',
            'expected an array of model class names, got \'role\' (string).',
        );
    }

    /**
     * Invalid `models.*` entries with the reason each is refused for.
     *
     * @return iterable<string, array{string, mixed, string}>
     */
    public static function invalidModelProvider(): iterable
    {
        yield 'null role' => ['role', null, 'expected a class-string, got \'null\' (null).'];
        yield 'integer role' => ['role', 42, 'expected a class-string, got 42 (int).'];
        yield 'empty role' => ['role', '', 'expected a class-string, got \'\' (string).'];
        yield 'missing role class' => ['role', 'App\Models\Missing', 'class \'App\Models\Missing\' does not exist.'];
        yield 'unrelated role class' => ['role', \stdClass::class, 'class \'stdClass\' is neither ' . Role::class . ' nor a subclass of it.'];
        yield 'permission as role' => ['role', Permission::class, 'class \'' . Permission::class . '\' is neither ' . Role::class . ' nor a subclass of it.'];
        yield 'role as permission' => ['permission', Role::class, 'class \'' . Role::class . '\' is neither ' . Permission::class . ' nor a subclass of it.'];
        yield 'role subclass as policy' => ['policy', CustomRole::class, 'class \'' . CustomRole::class . '\' is neither ' . Policy::class . ' nor a subclass of it.'];
    }

    /**
     * Every invalid `models.*` entry is refused with its own key and reason.
     *
     * @param  string  $key
     * @param  mixed  $class
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidModelProvider')]
    public function testInvalidModelEntryIsRejected(string $key, mixed $class, string $reason): void
    {
        $this->assertRejected(
            fn () => $this->validateWithModels([$key => $class]),
            "authorization.models.{$key}",
            $reason,
        );
    }

    /**
     * A bad `models.*` entry fails the provider's boot.
     *
     * @return void
     */
    public function testInvalidModelEntryFailsBoot(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.models.role', \stdClass::class);

        $this->assertRejected(
            fn () => (new AuthorizationServiceProvider($this->app))->boot(),
            'authorization.models.role',
            'class \'stdClass\' is neither ' . Role::class . ' nor a subclass of it.',
        );
    }

    /**
     * Run the validator over the package config with the given `models` block.
     *
     * @param  array<string, mixed>  $models
     * @return void
     */
    private function validateWithModels(array $models): void
    {
        $config           = $this->authorizationConfig();
        $config['models'] = $models;

        ConfigValidator::validate($config, $this->app);
    }

    /**
     * Return the merged package config.
     *
     * @return array<string, mixed>
     */
    private function authorizationConfig(): array
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject

        /** @var array<string, mixed> */
        return (array) $config->get('authorization');
    }

    /**
     * Assert the callback is refused with the given config key and reason.
     *
     * @param  callable(): mixed  $callback
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    private function assertRejected(callable $callback, string $key, string $reason): void
    {
        try {
            $callback();
            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }
}
