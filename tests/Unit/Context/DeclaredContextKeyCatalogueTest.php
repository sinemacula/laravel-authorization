<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Context\AssuranceKeys;
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
            'resource.id'              => new ContextKey('resource.id', ContextKeyType::STRING),
            'resource.tenant.id'       => new ContextKey('resource.tenant.id', ContextKeyType::STRING),
            'resource.tenant.type'     => new ContextKey('resource.tenant.type', ContextKeyType::STRING),
            'resource.type'            => new ContextKey('resource.type', ContextKeyType::STRING),
            'subject.id'               => new ContextKey('subject.id', ContextKeyType::STRING),
            'subject.tenant.id'        => new ContextKey('subject.tenant.id', ContextKeyType::STRING),
            'subject.tenant.type'      => new ContextKey('subject.tenant.type', ContextKeyType::STRING),
            'subject.type'             => new ContextKey('subject.type', ContextKeyType::STRING),
        ], $catalogue->keys());
        self::assertSame(['authentication', 'environment', 'request', 'resource', 'subject'], $catalogue->namespaces());
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
        self::assertSame(['authentication', 'environment', 'input', 'request', 'resource', 'subject', 'tenant'], $catalogue->namespaces());
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
        self::assertSame(['alpha', 'authentication', 'device', 'environment', 'request', 'resource', 'subject'], $catalogue->namespaces());
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
            'resource.id',
            'resource.tenant.id',
            'resource.tenant.type',
            'resource.type',
            'subject.id',
            'subject.tenant.id',
            'subject.tenant.type',
            'subject.type',
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
        $ip        = $catalogue->find('request.ip');

        $catalogue->declare('request.ip', ContextKeyType::IP);
        $catalogue->declare('authentication.level', ContextKeyType::NUMBER, false);

        $level = $catalogue->find('authentication.level');

        $catalogue->declare('authentication.level', ContextKeyType::NUMBER, false);

        self::assertEquals(new ContextKey('request.ip', ContextKeyType::IP), $catalogue->find('request.ip'));
        self::assertEquals(new ContextKey('authentication.level', ContextKeyType::NUMBER, false), $catalogue->find('authentication.level'));
        self::assertSame($ip, $catalogue->find('request.ip'));
        self::assertSame($level, $catalogue->find('authentication.level'));
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
     * Declaring a key again with another type, or once the assurance keys are
     * read with another testability, is refused, and leaves the declaration as
     * it was.
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
        $catalogue->keys();

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
     * Provide the namespaces whose keys only the package and the attribute
     * providers declare.
     *
     * @return iterable<string, array{string}>
     */
    public static function attributeNamespaceProvider(): iterable
    {
        yield 'resource' => ['resource'];
        yield 'subject' => ['subject'];
    }

    /**
     * A key under `subject` or `resource` is refused, whether declared or
     * registered, and is not declared, while the built-ins stay as they were.
     *
     * @param  string  $namespace
     * @return void
     */
    #[DataProvider('attributeNamespaceProvider')]
    public function testRefusesAKeyUnderAnAttributeNamespace(string $namespace): void
    {
        $reason = "is under the namespace '{$namespace}', whose keys are the package's built-ins and those an attribute provider declares; "
            . 'register a provider in authorization.attributes.subjects or authorization.attributes.resources.';
        $catalogue = new DeclaredContextKeyCatalogue;

        try {
            $catalogue->declare("{$namespace}.email", ContextKeyType::STRING);

            self::fail('A key under an attribute namespace is refused on declare.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame("Context key '{$namespace}.email' {$reason}", $exception->getMessage());
        }

        try {
            $catalogue->register($namespace, ['status' => 'string']);

            self::fail('A key under an attribute namespace is refused on register.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame("Context key '{$namespace}.status' {$reason}", $exception->getMessage());
        }

        self::assertNull($catalogue->find("{$namespace}.email"));
        self::assertNull($catalogue->find("{$namespace}.status"));
        self::assertEquals(new ContextKey("{$namespace}.id", ContextKeyType::STRING), $catalogue->find("{$namespace}.id"));
    }

    /**
     * `principal` is no reserved namespace any more: its keys are declared like
     * any other's.
     *
     * @return void
     */
    public function testAcceptsAKeyUnderPrincipalLikeAnyOther(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue;

        self::assertFalse($catalogue->permits('principal.id'));

        $catalogue->declare('principal.id', ContextKeyType::STRING);

        self::assertTrue($catalogue->permits('principal.id'));
    }

    /**
     * The attributes the providers declare enter the catalogue under their
     * namespace, typed by name or as a type, two providers may declare one key
     * alike, and one provider may declare a key under another provider's.
     *
     * @return void
     */
    public function testDeclaresTheProvidersAttributes(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue(['tenant' => ['plan' => 'string']], [
            'resource' => [
                'App\PostAttributes'    => ['status' => 'string', 'owner.id' => ContextKeyType::STRING],
                'App\CommentAttributes' => ['status' => 'string', 'owner' => 'string', 'owner-id' => 'string'],
            ],
            'subject' => ['App\UserAttributes' => ['clearance' => 'number']],
        ]);

        self::assertEquals(new ContextKey('resource.status', ContextKeyType::STRING), $catalogue->find('resource.status'));
        self::assertEquals(new ContextKey('resource.owner.id', ContextKeyType::STRING), $catalogue->find('resource.owner.id'));
        self::assertEquals(new ContextKey('resource.owner', ContextKeyType::STRING), $catalogue->find('resource.owner'));
        self::assertEquals(new ContextKey('subject.clearance', ContextKeyType::NUMBER), $catalogue->find('subject.clearance'));
        self::assertTrue($catalogue->permits('subject.clearance', 'gte'));
        self::assertTrue($catalogue->permits('tenant.plan'));
    }

    /**
     * Provide attribute declarations the catalogue refuses, with the reason.
     *
     * @return iterable<string, array{array<string, array<string, array<string, string>>>, string}>
     */
    public static function invalidAttributesProvider(): iterable
    {
        yield 'another namespace' => [
            ['tenant' => ['App\Plan' => ['plan' => 'string']]],
            'Attribute provider App\Plan supplies the namespace \'tenant\'; attributes belong under \'subject\' or \'resource\'.',
        ];

        foreach (['id', 'type', 'tenant', 'tenant.id', 'tenant.name', 'id.value'] as $path) {
            yield "the built-in {$path}" => [
                ['resource' => ['App\Post' => [$path => 'string']]],
                "Attribute provider App\\Post declares 'resource.{$path}', which is a built-in or under one; no provider may declare 'id', 'type' or 'tenant'.",
            ];
        }

        yield 'a conflicting type' => [
            ['subject' => ['App\User' => ['level' => 'number'], 'App\Admin' => ['level' => 'string']]],
            'Attribute provider App\Admin declares \'subject.level\' as string, but another provider declares it as number.',
        ];
        yield 'an unknown type' => [
            ['subject' => ['App\User' => ['level' => 'integer']]],
            'Context key \'subject.level\' has an unknown type \'integer\'; use one of string, number, bool, time, ip, list.',
        ];
        yield 'a key under another' => [
            ['resource' => ['App\Post' => ['owner' => 'string', 'owner.id' => 'string']]],
            'Attribute provider App\Post declares \'resource.owner.id\' under \'resource.owner\', which it also declares; declare the keys under \'resource.owner\' alone.',
        ];
        yield 'a key deep under another declared after it' => [
            ['subject' => ['App\User' => ['team.lead.id' => 'string', 'status' => 'string', 'team' => 'list']]],
            'Attribute provider App\User declares \'subject.team.lead.id\' under \'subject.team\', which it also declares; declare the keys under \'subject.team\' alone.',
        ];
        yield 'a malformed path' => [
            ['subject' => ['App\User' => ['level..x' => 'string']]],
            'Context key \'subject.level..x\' must be',
        ];
    }

    /**
     * An attribute declaration outside `subject` and `resource`, of a built-in
     * or a key under one, of a key another provider declares with another type,
     * of a key under another the provider declares, of an unknown type or with
     * a malformed path is refused.
     *
     * @param  array<string, array<string, array<string, string>>>  $attributes
     * @param  string  $message
     * @return void
     */
    #[DataProvider('invalidAttributesProvider')]
    public function testRefusesAnInvalidAttributeDeclaration(array $attributes, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new DeclaredContextKeyCatalogue([], $attributes);
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

    /**
     * An assurance key of `authentication`, or of a namespace the
     * authentication context contributes, is declared untestable however it is
     * declared, so a condition may not test it but a reference may read it.
     *
     * @return void
     */
    public function testAssuranceKeysAreAlwaysUntestable(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue(['authentication' => ['amr' => 'list', 'auth_time' => 'time']], [], ['mfa']);

        $catalogue->declare('mfa.multifactor', ContextKeyType::BOOL);
        $catalogue->register('mfa', ['seconds_since_step_up' => 'number', 'enrolled' => 'bool']);
        $catalogue->register('sso', ['assurance_level' => 'string']);

        foreach (['authentication.amr', 'authentication.auth_time', 'mfa.multifactor', 'mfa.seconds_since_step_up'] as $path) {
            self::assertFalse($catalogue->find($path)?->isTestable, "{$path} is testable.");
            self::assertFalse($catalogue->permits($path, 'eq'));
            self::assertTrue($catalogue->permits($path));
        }

        self::assertTrue($catalogue->find('mfa.enrolled')?->isTestable);
        self::assertTrue($catalogue->find('sso.assurance_level')?->isTestable);
        self::assertTrue($catalogue->find('authentication.guard')?->isTestable);
    }

    /**
     * Declaring an assurance key again, testable or not, changes nothing and is
     * not refused.
     *
     * @return void
     */
    public function testRedeclaringAnAssuranceKeyIsAccepted(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue;

        $catalogue->declare('authentication.verification_age', ContextKeyType::NUMBER);
        $catalogue->declare('authentication.verification_age', ContextKeyType::NUMBER, false);
        $catalogue->declare('authentication.verification_age', ContextKeyType::NUMBER, true);

        self::assertEquals(new ContextKey('authentication.verification_age', ContextKeyType::NUMBER, false), $catalogue->find('authentication.verification_age'));
    }

    /**
     * The names the authentication context declares make keys of its namespaces
     * untestable, exact names and prefixes alike, and the keys are listed as a
     * policy may read them.
     *
     * @return void
     */
    public function testDeclaredAssuranceKeysAreUntestable(): void
    {
        $keys      = ['mfa' => ['level' => 'number', 'enrolled' => 'bool'], 'sso' => ['provider_name' => 'string']];
        $catalogue = new DeclaredContextKeyCatalogue($keys, [], new AssuranceKeys(['mfa', 'sso'], ['level', 'provider_*']));

        self::assertFalse($catalogue->permits('mfa.level', 'gte'));
        self::assertFalse($catalogue->permits('sso.provider_name', 'eq'));
        self::assertTrue($catalogue->permits('sso.provider_name'));
        self::assertTrue($catalogue->permits('mfa.enrolled', 'bool'));
        self::assertEquals(new ContextKey('mfa.level', ContextKeyType::NUMBER, false), $catalogue->keys()['mfa.level']);
        self::assertEquals(new ContextKey('sso.provider_name', ContextKeyType::STRING, false), $catalogue->keys()['sso.provider_name']);
        self::assertEquals(new ContextKey('mfa.enrolled', ContextKeyType::BOOL, true), $catalogue->keys()['mfa.enrolled']);
    }

    /**
     * The assurance keys given as a closure are read at the first use that
     * needs them, never when the catalogue is built or a key is declared, and
     * only once.
     *
     * @return void
     */
    public function testReadsTheAssuranceKeysOnceAtFirstUse(): void
    {
        /** @var \ArrayObject<int, bool> $reads */
        $reads  = new \ArrayObject;
        $source = static function () use ($reads): AssuranceKeys {
            $reads->append(true);

            return new AssuranceKeys(['mfa'], ['level']);
        };

        $catalogue = new DeclaredContextKeyCatalogue(['mfa' => ['level' => 'number']], [], $source);
        $catalogue->declare('mfa.enrolled', ContextKeyType::BOOL);
        $catalogue->register('mfa', ['factors' => 'list']);

        self::assertCount(0, $reads);
        self::assertFalse($catalogue->permits('mfa.level', 'eq'));
        self::assertFalse($catalogue->find('mfa.level')?->isTestable);
        self::assertTrue($catalogue->find('mfa.enrolled')?->isTestable);
        self::assertCount(3, \array_intersect_key($catalogue->keys(), ['mfa.level' => true, 'mfa.enrolled' => true, 'mfa.factors' => true]));
        self::assertCount(1, $reads);
    }

    /**
     * Declaring a key again with another testability reads nothing: the first
     * read judges it, accepting an assurance key and refusing any other with
     * the refusal the declaration would have thrown, at that read and every
     * later one.
     *
     * @return void
     */
    public function testRedeclaringWithAnotherTestabilityIsJudgedAtTheFirstRead(): void
    {
        /** @var \ArrayObject<int, bool> $reads */
        $reads  = new \ArrayObject;
        $source = static function () use ($reads): AssuranceKeys {
            $reads->append(true);

            return new AssuranceKeys(['mfa'], ['level']);
        };

        $catalogue = new DeclaredContextKeyCatalogue([], [], $source);
        $catalogue->declare('mfa.level', ContextKeyType::NUMBER);
        $catalogue->declare('mfa.level', ContextKeyType::NUMBER, false);
        $catalogue->declare('mfa.enrolled', ContextKeyType::BOOL);
        $catalogue->declare('mfa.enrolled', ContextKeyType::BOOL, false);

        self::assertCount(0, $reads);

        foreach ([static fn (): ?ContextKey => $catalogue->find('mfa.level'), static fn (): bool => $catalogue->permits('mfa.enrolled', 'eq')] as $read) {
            try {
                $read();
                self::fail('A key declared again with another testability was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('Context key \'mfa.enrolled\' is already declared as bool.', $exception->getMessage());
            }
        }

        self::assertCount(2, $reads);
    }

    /**
     * An assurance key declared again with another testability before the first
     * read is accepted there, and stays untestable.
     *
     * @return void
     */
    public function testAnAssuranceKeyDeclaredAgainBeforeTheFirstReadIsAccepted(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue([], [], static fn (): AssuranceKeys => new AssuranceKeys(['mfa'], ['level']));
        $catalogue->declare('mfa.level', ContextKeyType::NUMBER, false);
        $catalogue->declare('mfa.level', ContextKeyType::NUMBER);
        $catalogue->declare('mfa.enrolled', ContextKeyType::BOOL);

        self::assertEquals(new ContextKey('mfa.level', ContextKeyType::NUMBER, false), $catalogue->find('mfa.level'));
        self::assertTrue($catalogue->permits('mfa.enrolled', 'eq'));
    }

    /**
     * Once the assurance keys are read, a key declared again with another
     * testability is judged at once: an assurance key is accepted, and any
     * other refused, leaving the catalogue as it was.
     *
     * @return void
     */
    public function testRedeclaringAfterTheFirstReadIsJudgedAtOnce(): void
    {
        $catalogue = new DeclaredContextKeyCatalogue(['mfa' => ['level' => 'number', 'enrolled' => 'bool']], [], new AssuranceKeys(['mfa'], ['level']));

        self::assertTrue($catalogue->permits('mfa.enrolled', 'eq'));

        $catalogue->declare('mfa.level', ContextKeyType::NUMBER, false);

        try {
            $catalogue->declare('mfa.enrolled', ContextKeyType::BOOL, false);
            self::fail('A key declared again with another testability was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Context key \'mfa.enrolled\' is already declared as bool.', $exception->getMessage());
        }

        self::assertTrue($catalogue->permits('mfa.enrolled', 'eq'));
        self::assertFalse($catalogue->permits('mfa.level', 'eq'));
    }

    /**
     * A key declared with another type is refused at once, stated as first
     * declared, without reading the assurance keys.
     *
     * @return void
     */
    public function testATypeRefusalStatesTheKeyAsDeclaredWithoutReadingTheContext(): void
    {
        /** @var \ArrayObject<int, bool> $reads */
        $reads     = new \ArrayObject;
        $catalogue = new DeclaredContextKeyCatalogue(['mfa' => ['level' => 'number']], [], static function () use ($reads): AssuranceKeys {
            $reads->append(true);

            return new AssuranceKeys(['mfa'], ['level']);
        });

        $catalogue->declare('mfa.factors', ContextKeyType::LIST, false);

        foreach (['mfa.level' => 'number.', 'mfa.factors' => 'list, untestable.'] as $path => $declared) {
            try {
                $catalogue->declare($path, ContextKeyType::STRING);
                self::fail('A key declared again with another type was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame("Context key '{$path}' is already declared as {$declared}", $exception->getMessage());
            }
        }

        self::assertCount(0, $reads);
    }

    /**
     * A malformed declaration fails closed: every read that needs the assurance
     * keys throws, each time, rather than leaving a key testable.
     *
     * @return void
     */
    public function testAMalformedDeclarationFailsClosed(): void
    {
        /** @var \ArrayObject<int, bool> $reads */
        $reads     = new \ArrayObject;
        $catalogue = new DeclaredContextKeyCatalogue(['mfa' => ['level' => 'number']], [], static function () use ($reads): AssuranceKeys {
            $reads->append(true);

            return new AssuranceKeys(['mfa'], ['le.vel']);
        });

        foreach ([static fn (): bool => $catalogue->permits('mfa.level', 'eq'), static fn (): ?ContextKey => $catalogue->find('mfa.level')] as $read) {
            try {
                $read();
                self::fail('A malformed declaration was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString('\'le.vel\'', $exception->getMessage());
            }
        }

        self::assertCount(2, $reads);
    }
}
