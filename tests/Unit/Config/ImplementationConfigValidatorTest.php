<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\ImplementationConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use Tests\Concerns\ReadsRefusedSettings;
use Tests\Feature\Stubs\StubTenantTree;

/**
 * Unit tests for the shared validation of a config key naming the class that
 * implements a contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImplementationConfigValidator::class)]
final class ImplementationConfigValidatorTest extends TestCase
{
    use ReadsRefusedSettings;

    /** @var string The key the tests validate under. */
    private const string KEY = 'authorization.example';

    /** @var string The reason a null value is refused with. */
    private const string REQUIRED = 'an example class is required.';

    /**
     * A class implementing the contract is accepted.
     *
     * @return void
     */
    public function testAcceptsAnImplementingClass(): void
    {
        ImplementationConfigValidator::validate(self::KEY, FlatTenantTree::class, TenantTree::class, self::REQUIRED);
        ImplementationConfigValidator::validate(self::KEY, StubTenantTree::class, TenantTree::class, self::REQUIRED);

        $this->addToAssertionCount(2);
    }

    /**
     * Provide values that name no implementing class, with the reason each is
     * refused.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function refusedProvider(): iterable
    {
        yield 'null' => [null, self::REQUIRED];
        yield 'an empty string' => ['', 'expected a class-string, got string.'];
        yield 'a number' => [42, 'expected a class-string, got int.'];
        yield 'an array' => [[FlatTenantTree::class], 'expected a class-string, got array.'];
        yield 'a missing class' => ['App\Missing\Tree', 'class \'App\Missing\Tree\' does not exist.'];
        yield 'another class' => [\stdClass::class, 'class \'stdClass\' does not implement ' . TenantTree::class . '.'];
    }

    /**
     * A value naming no implementing class is refused under the key, with its
     * reason.
     *
     * @param  mixed  $value
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedProvider')]
    public function testRefusesAValueNamingNoImplementation(mixed $value, string $reason): void
    {
        try {
            ImplementationConfigValidator::validate(self::KEY, $value, TenantTree::class, self::REQUIRED);
            self::fail('The value was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString(self::KEY, $exception->getMessage());
            self::assertStringContainsString($reason, $exception->getMessage());
        }
    }

    /**
     * Each refusal states its code, what the setting expects, naming the
     * contract, and the type found.
     *
     * @return void
     */
    public function testEachRefusalIsStructured(): void
    {
        $check = static fn (mixed $value): \Closure => static function () use ($value): void {
            ImplementationConfigValidator::validate('authorization.tenant_tree', $value, TenantTree::class, 'required');
        };
        $expected = 'the name of a class implementing ' . TenantTree::class;

        self::assertSame(['authorization.tenant_tree', 'required', $expected, 'null'], self::refusedSetting($check(null)));
        self::assertSame(['authorization.tenant_tree', 'invalid_type', $expected, 'int'], self::refusedSetting($check(3)));
        self::assertSame(['authorization.tenant_tree', 'unknown_class', $expected, 'string'], self::refusedSetting($check('Missing\Tree')));
        self::assertSame(['authorization.tenant_tree', 'not_implemented', $expected, 'string'], self::refusedSetting($check(\stdClass::class)));
    }
}
