<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Context\ContextKey;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Evaluation\PolicyValidator;

/**
 * Unit tests for `DeclaredContextKeyCatalogue`, the context keys declared to
 * the package.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DeclaredContextKeyCatalogue::class)]
final class DeclaredContextKeyCatalogueTest extends TestCase
{
    /**
     * The catalogue declares the package's own keys, each testable, with its
     * type.
     *
     * @return void
     */
    public function testDeclaresThePackagesOwnKeys(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue;

        self::assertInstanceOf(ContextKeyCatalogue::class, $catalogue);
        self::assertEquals([
            'authentication.guard'     => new ContextKey('authentication.guard', ContextKeyType::STRING),
            'authentication.user_id'   => new ContextKey('authentication.user_id', ContextKeyType::STRING),
            'authentication.user_type' => new ContextKey('authentication.user_type', ContextKeyType::STRING),
            'environment.time'         => new ContextKey('environment.time', ContextKeyType::TIME),
            'request.ip'               => new ContextKey('request.ip', ContextKeyType::IP),
            'request.method'           => new ContextKey('request.method', ContextKeyType::STRING),
            'request.route'            => new ContextKey('request.route', ContextKeyType::STRING),
        ], $catalogue->keys());
        self::assertSame(['authentication', 'environment', 'request'], $catalogue->namespaces());
    }

    /**
     * A policy may read a declared key, and test it with an operator its type
     * suits, an `_if_exists` form of one, or `null`, but never an undeclared
     * key, nor test an untestable one, nor with an operator that does not suit
     * its type.
     *
     * @return void
     */
    public function testPermitsDeclaredKeysWithTheOperatorsTheirTypesSuit(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue;

        $catalogue->declare('mfa.assurance', ContextKeyType::STRING, false);

        self::assertTrue($catalogue->permits('request.ip'));
        self::assertTrue($catalogue->permits('request.ip', 'ip_in'));
        self::assertTrue($catalogue->permits('request.ip', 'ip_in_if_exists'));
        self::assertTrue($catalogue->permits('request.ip', 'null'));
        self::assertTrue($catalogue->permits('environment.time', 'between'));
        self::assertTrue($catalogue->permits('mfa.assurance'));

        self::assertFalse($catalogue->permits('request.ip', 'gt'));
        self::assertFalse($catalogue->permits('request.ip', 'unknown'));
        self::assertFalse($catalogue->permits('environment.time', 'eq'));
        self::assertFalse($catalogue->permits('mfa.assurance', 'eq'));
        self::assertFalse($catalogue->permits('mfa.assurance', 'null'));
        self::assertFalse($catalogue->permits('request'));
        self::assertFalse($catalogue->permits('request.ip.v4'));
        self::assertFalse($catalogue->permits('input.post', 'eq'));
    }

    /**
     * The keys given at construction are registered by namespace, each a path
     * within it, with a type given by name or as a type.
     *
     * @return void
     */
    public function testRegistersTheKeysGivenAtConstruction(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue([
            'tenant' => ['plan' => 'string', 'limits.seats' => ContextKeyType::NUMBER],
            'input'  => ['post.status' => 'string'],
        ]);

        self::assertEquals(new ContextKey('tenant.plan', ContextKeyType::STRING), $catalogue->find('tenant.plan'));
        self::assertEquals(new ContextKey('tenant.limits.seats', ContextKeyType::NUMBER), $catalogue->find('tenant.limits.seats'));
        self::assertEquals(new ContextKey('input.post.status', ContextKeyType::STRING), $catalogue->find('input.post.status'));
        self::assertSame(['authentication', 'environment', 'input', 'request', 'tenant'], $catalogue->namespaces());
    }

    /**
     * A key is found only by its full dot path.
     *
     * @return void
     */
    public function testFindsAKeyByItsFullPath(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue;

        self::assertEquals(new ContextKey('request.ip', ContextKeyType::IP), $catalogue->find('request.ip'));
        self::assertNull($catalogue->find('request'));
        self::assertNull($catalogue->find('ip'));
        self::assertNull($catalogue->find('request.ip.v4'));
        self::assertNull($catalogue->find('input.anything'));
    }

    /**
     * A key declared after construction, such as by a service provider, is
     * found, may be declared untestable, and is listed in order of path.
     *
     * @return void
     */
    public function testDeclaresAndRegistersKeysLater(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue;

        $catalogue->declare('authentication.level', ContextKeyType::NUMBER, false);
        $catalogue->register('device', ['id' => 'string', 'trusted' => 'bool']);
        $catalogue->register('alpha', ['tags' => ContextKeyType::LIST]);

        self::assertEquals(new ContextKey('authentication.level', ContextKeyType::NUMBER, false), $catalogue->find('authentication.level'));
        self::assertEquals(new ContextKey('device.trusted', ContextKeyType::BOOL), $catalogue->find('device.trusted'));
        self::assertSame(['alpha', 'authentication', 'device', 'environment', 'request'], $catalogue->namespaces());
        self::assertSame([
            'alpha.tags',
            'authentication.guard',
            'authentication.level',
            'authentication.user_id',
            'authentication.user_type',
            'device.id',
            'device.trusted',
            'environment.time',
            'request.ip',
            'request.method',
            'request.route',
        ], \array_keys($catalogue->keys()));
    }

    /**
     * Declaring a key again as it was declared changes nothing.
     *
     * @return void
     */
    public function testDeclaringAKeyAgainAlikeChangesNothing(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue(['request' => ['ip' => 'ip']]);

        $catalogue->declare('request.ip', ContextKeyType::IP);
        $catalogue->declare('authentication.level', ContextKeyType::NUMBER, false);
        $catalogue->declare('authentication.level', ContextKeyType::NUMBER, false);

        self::assertEquals(new ContextKey('request.ip', ContextKeyType::IP), $catalogue->find('request.ip'));
        self::assertEquals(new ContextKey('authentication.level', ContextKeyType::NUMBER, false), $catalogue->find('authentication.level'));
    }

    /**
     * Provide redeclarations that conflict with a declaration, with the reason
     * each is refused.
     *
     * @return iterable<string, array{string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType, bool, string}>
     */
    public static function conflictProvider(): iterable
    {
        yield 'another type' => ['request.ip', ContextKeyType::STRING, true, 'Context key \'request.ip\' is already declared as ip.'];
        yield 'untestable' => ['request.ip', ContextKeyType::IP, false, 'Context key \'request.ip\' is already declared as ip.'];
        yield 'testable' => ['authentication.level', ContextKeyType::NUMBER, true, 'Context key \'authentication.level\' is already declared as number, untestable.'];
    }

    /**
     * Declaring a key again with another type or testability is refused, and
     * leaves the declaration as it was.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\Authorization\Enums\ContextKeyType  $type
     * @param  bool  $isTestable
     * @param  string  $message
     * @return void
     */
    #[DataProvider('conflictProvider')]
    public function testRefusesAConflictingDeclaration(string $path, ContextKeyType $type, bool $isTestable, string $message): void
    {
        $catalogue = new DeclaredContextKeyCatalogue;
        $catalogue->declare('authentication.level', ContextKeyType::NUMBER, false);

        $declared = $catalogue->find($path);

        try {
            $catalogue->declare($path, $type, $isTestable);

            self::fail('A conflicting declaration is refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }

        self::assertSame($declared, $catalogue->find($path));
    }

    /**
     * Provide paths that are not a namespace and one or more segments in the
     * key syntax.
     *
     * @return iterable<string, array{string}>
     */
    public static function invalidPathProvider(): iterable
    {
        yield 'a namespace alone' => ['request'];
        yield 'empty' => [''];
        yield 'an empty segment' => ['request..ip'];
        yield 'a trailing dot' => ['request.'];
        yield 'a leading dot' => ['.ip'];
        yield 'a namespace starting with a digit' => ['1request.ip'];
        yield 'a namespace with a dash' => ['re-quest.ip'];
        yield 'a space' => ['request.client ip'];
        yield 'a wildcard' => ['request.*'];
        yield 'too long' => ['input.' . \str_repeat('a', PolicyValidator::KEY_LENGTH - 5)];
    }

    /**
     * A path that is not a namespace and one or more segments in the key
     * syntax, or is too long, is refused.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('invalidPathProvider')]
    public function testRefusesAMalformedPath(string $path): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(
            "Context key '{$path}' must be a namespace and one or more '.'-separated segments of letters, digits, '_' and '-', and at most 128 characters.",
        );

        (new DeclaredContextKeyCatalogue)->declare($path, ContextKeyType::STRING);
    }

    /**
     * A path of the longest length, with dashes in its segments, is accepted.
     *
     * @return void
     */
    public function testAcceptsTheLongestPath(): void
    {
        $path      = 'input.' . \str_repeat('a', PolicyValidator::KEY_LENGTH - 8) . '-b';
        $catalogue = new DeclaredContextKeyCatalogue;

        $catalogue->declare($path, ContextKeyType::STRING);

        self::assertSame(PolicyValidator::KEY_LENGTH, \strlen($path));
        self::assertNotNull($catalogue->find($path));
    }

    /**
     * A key registered with a name that is not a type is refused, naming the
     * types, and so is a malformed path within a namespace.
     *
     * @return void
     */
    public function testRefusesAnUnknownTypeOrPath(): void
    {
        try {
            new DeclaredContextKeyCatalogue(['tenant' => ['plan' => 'text']]);

            self::fail('An unknown type is refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Context key \'tenant.plan\' has an unknown type \'text\'; use one of string, number, bool, time, ip, list.', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Context key \'tenant.\' must be');

        (new DeclaredContextKeyCatalogue)->register('tenant', ['' => 'string']);
    }
}
