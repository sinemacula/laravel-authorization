<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\ConfigValue;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Fixtures\ExtendedRole;

/**
 * Unit tests for reading a package model's class at run time: a model left out
 * is the package's own, and a class or block changed to one that cannot name a
 * class is refused, never read as the package's model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelClasses::class)]
#[CoversClass(ConfigValue::class)]
final class ModelClassesTest extends TestCase
{
    /**
     * A configured class is read as it is.
     *
     * @return void
     */
    public function testAConfiguredClassIsRead(): void
    {
        $config = new Repository(['authorization' => ['models' => ['role' => ExtendedRole::class]]]);

        self::assertSame(ExtendedRole::class, ModelClasses::get('role', $config));
    }

    /**
     * A model the configuration leaves out, or a configuration without the
     * block or the authorization config, is the package's own.
     *
     * @return void
     */
    public function testAModelLeftOutIsThePackagesOwn(): void
    {
        $config = new Repository(['authorization' => ['models' => ['role' => ExtendedRole::class]]]);

        self::assertSame(Permission::class, ModelClasses::get('permission', $config));
        self::assertSame(Policy::class, ModelClasses::get('policy', $config));
        self::assertSame(Role::class, ModelClasses::get('role', new Repository(['authorization' => []])));
        self::assertSame(Role::class, ModelClasses::get('role', new Repository));
    }

    /**
     * Return each configuration refused, with the path it is refused under and
     * why.
     *
     * @return iterable<string, array{array<string, mixed>, string, string}>
     */
    public static function refusedConfigs(): iterable
    {
        yield 'a null class' => [['models' => ['role' => null]], 'authorization.models.role', 'expected a class-string, got \'null\' (null).'];
        yield 'an empty class' => [['models' => ['role' => '']], 'authorization.models.role', 'expected a class-string, got \'\' (string).'];
        yield 'an int class' => [['models' => ['role' => 5]], 'authorization.models.role', 'expected a class-string, got 5 (int).'];
        yield 'a null block' => [['models' => null], 'authorization.models', 'expected an array, got \'null\' (null).'];
        yield 'a string block' => [['models' => 'role'], 'authorization.models', 'expected an array, got \'role\' (string).'];
    }

    /**
     * A class, or the block holding it, that cannot name a class is refused
     * under its own path, never read as the package's model.
     *
     * @param  array<string, mixed>  $authorization
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedConfigs')]
    public function testAClassThatCannotNameAModelIsRefused(array $authorization, string $key, string $reason): void
    {
        try {
            ModelClasses::get('role', new Repository(['authorization' => $authorization]));

            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }
}
