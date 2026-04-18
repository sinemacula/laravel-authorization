<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Tests\TestCase;

/**
 * Mutation-killer coverage for exception message strings assembled via `.`
 * concat. Each test pins the exact rendered message content so
 * ConcatOperandRemoval / Concat reordering mutations fail.
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
#[CoversClass(\SineMacula\Laravel\Authorization\Http\Middleware\AuthorizationMiddlewareMisconfiguredException::class)]
#[CoversClass(\SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException::class)]
final class ExceptionMessageKillersTest extends TestCase
{
    /**
     * `permission_enums` rejects a scalar with a message that names the debug
     * type at the end. Pins the full concat.
     *
     * @return void
     */
    public function testPermissionEnumsScalarMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', 'not-an-array');

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString('authorization.permission_enums', $exception->getMessage());
            self::assertStringContainsString('expected an array of enum class names, got string.', $exception->getMessage());
        }
    }

    /**
     * A non-existent `permission_enums` entry yields a message that quotes the
     * class name in single quotes and says "does not exist.".
     *
     * @return void
     */
    public function testPermissionEnumsUnknownClassMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', ['App\NoSuch\ClassX']);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString('class \'App\NoSuch\ClassX\' does not exist.', $exception->getMessage());
        }
    }

    /**
     * An existing class that doesn't implement `PermissionEnum` yields a
     * message naming the class and the contract FQCN.
     *
     * @return void
     */
    public function testPermissionEnumsNonContractMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [\stdClass::class]);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString('class \'stdClass\' does not implement', $exception->getMessage());
            self::assertStringContainsString(\SineMacula\Laravel\Authorization\Contracts\PermissionEnum::class, $exception->getMessage());
            self::assertStringEndsWith('.', $exception->getMessage());
        }
    }

    /**
     * `permission_enums` entries must be non-empty class-strings.
     *
     * @return void
     */
    public function testPermissionEnumsEmptyEntryMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', ['']);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString('authorization.permission_enums.0', $exception->getMessage());
            self::assertStringContainsString('non-empty class-string', $exception->getMessage());
        }
    }

    /**
     * `permission_providers` with a scalar payload yields the typed message
     * naming the config key and the debug type.
     *
     * @return void
     */
    public function testPermissionProvidersScalarMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_providers', 42);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString('authorization.permission_providers', $exception->getMessage());
            self::assertStringContainsString('expected an array of class names, got int.', $exception->getMessage());
        }
    }

    /**
     * An unknown `permission_providers` class yields the correctly quoted
     * message.
     *
     * @return void
     */
    public function testPermissionProvidersUnknownClassMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_providers', ['App\NoSuch\ProviderX']);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString('class \'App\NoSuch\ProviderX\' does not exist.', $exception->getMessage());
        }
    }

    /**
     * `cache.store` non-string message names the offending type.
     *
     * @return void
     */
    public function testCacheStoreNonStringMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.cache.store', 42);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString('authorization.cache.store', $exception->getMessage());
            self::assertStringContainsString('expected a cache-store name string, got 42 (int).', $exception->getMessage());
        }
    }

    /**
     * `AuthorizationMiddlewareMisconfiguredException` shortens the FQCN to the
     * trailing class name and embeds it at the exact position in the message.
     * Pins the `strrpos + 1` arithmetic against Increment / Decrement /
     * UnwrapSubstr mutations.
     *
     * @return void
     */
    public function testMisconfiguredMiddlewareExceptionShortensContractFqcn(): void
    {
        $exception = new \SineMacula\Laravel\Authorization\Http\Middleware\AuthorizationMiddlewareMisconfiguredException(
            contract: 'SineMacula\Laravel\Authorization\Contracts\SupportsRoles',
            middleware: 'auth.role',
        );

        self::assertSame(
            'Middleware auth.role requires the authenticated identity to implement SupportsRoles; '
            . 'apply the appropriate trait on the user model or remove the middleware from this route.',
            $exception->getMessage(),
        );
    }

    /**
     * A contract with no namespace separator falls back to the raw string —
     * pins the `strrpos !== false` ternary false branch.
     *
     * @return void
     */
    public function testMisconfiguredMiddlewareExceptionHandlesUnqualifiedContract(): void
    {
        $exception = new \SineMacula\Laravel\Authorization\Http\Middleware\AuthorizationMiddlewareMisconfiguredException(
            contract: 'Bareword',
            middleware: 'auth.permission',
        );

        self::assertStringContainsString('implement Bareword;', $exception->getMessage());
    }

    /**
     * `GuardMismatchException` assembles its message via three concat segments
     * and carries HTTP status 422. Pins the concat content and the status code
     * against Increment / Decrement / ConcatOperandRemoval mutants.
     *
     * @return void
     */
    public function testGuardMismatchExceptionMessageAndCode(): void
    {
        $exception = new \SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException(
            roleName: 'editor',
            permissionName: 'posts:create',
            roleGuard: 'web',
            permissionGuard: 'api',
        );

        self::assertSame(
            'Guard mismatch: role \'editor\' (guard \'web\') cannot carry'
            . ' permission \'posts:create\' (guard \'api\').'
            . ' Scope one side to null for a guard-agnostic attachment, or match the guards.',
            $exception->getMessage(),
        );

        self::assertSame(422, $exception->getCode());
        self::assertSame('editor', $exception->getRoleName());
        self::assertSame('posts:create', $exception->getPermissionName());
        self::assertSame('web', $exception->getRoleGuard());
        self::assertSame('api', $exception->getPermissionGuard());
    }

    /**
     * `principal_resolver` non-string message names the offending type.
     *
     * @return void
     */
    public function testPrincipalResolverNonStringMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.principal_resolver', 42);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString('authorization.principal_resolver', $exception->getMessage());
            self::assertStringContainsString('expected a class-string', $exception->getMessage());
            self::assertStringContainsString('int', $exception->getMessage());
        }
    }
}
