<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Config\AttributeConfigValidator;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Tests\Concerns\ReadsRefusedSettings;
use Tests\Feature\Stubs\ConflictingResourceAttributes;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\Feature\Stubs\RecordingSubjectAttributes;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `AttributeConfigValidator`, the boot-time validation of
 * `authorization.attributes`: the resource and subject attribute providers and
 * the attributes they declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AttributeConfigValidator::class)]
final class AttributeConfigValidatorTest extends TestCase
{
    use ReadsRefusedSettings;

    /** @var string The config key every declaration fault is reported under. */
    private const string ATTRIBUTES = 'authorization.attributes';

    /** @var string Why no provider may declare a built-in. */
    private const string BUILT_INS = 'no provider may declare \'id\', \'type\' or \'tenant\'.';

    /** @var string How a provider must declare its attributes. */
    private const string TYPE_MAP = 'must declare its attributes as dot paths mapped to the names of their types, such as [\'status\' => \'string\'].';

    /**
     * Providers of each kind, registered by morph type, pass; so do two
     * declaring one key alike, one declaring its types as types and by name,
     * and an empty config, whose lists of providers are left out.
     *
     * @return void
     */
    public function testValidProvidersPass(): void
    {
        AttributeConfigValidator::validate([], $this->container());
        AttributeConfigValidator::validate(['resources' => [], 'subjects' => []], $this->container());
        AttributeConfigValidator::validate([
            'resources' => ['post' => RecordingResourceAttributes::class, 'page' => RecordingResourceAttributes::class],
            'subjects'  => ['user' => RecordingSubjectAttributes::class],
        ], $this->container());

        $this->container()->instance(ConflictingResourceAttributes::class, new ConflictingResourceAttributes(['state' => ContextKeyType::STRING, 'count' => 'number']));

        AttributeConfigValidator::validate(['resources' => ['post' => ConflictingResourceAttributes::class]], $this->container());

        $this->expectNotToPerformAssertions();
    }

    /**
     * Provide `attributes` configs that are refused, with the key and the
     * reason.
     *
     * @return iterable<string, array{0: mixed, 1: string, 2: string}>
     */
    public static function invalidConfigs(): iterable
    {
        yield 'not an array' => ['providers', self::ATTRIBUTES, 'expected an array, got \'providers\' (string).'];
        yield 'null' => [null, self::ATTRIBUTES, 'expected an array, got \'null\' (null).'];
        yield 'an unknown key' => [['resource' => []], self::ATTRIBUTES . '.resource', 'unknown key \'resource\'; expected one of resources, subjects.'];
        yield 'null resources' => [['resources' => null], self::ATTRIBUTES . '.resources', 'expected an array of morph types to class names, got null.'];
        yield 'null subjects' => [['subjects' => null], self::ATTRIBUTES . '.subjects', 'expected an array of morph types to class names, got null.'];
        yield 'resources that are not an array' => [
            ['resources' => RecordingResourceAttributes::class],
            self::ATTRIBUTES . '.resources',
            'expected an array of morph types to class names, got string.',
        ];
        yield 'subjects that are not an array' => [['subjects' => 1], self::ATTRIBUTES . '.subjects', 'expected an array of morph types to class names, got int.'];
        yield 'an entry not keyed by a morph type' => [
            ['resources' => [RecordingResourceAttributes::class]],
            self::ATTRIBUTES . '.resources',
            'each entry must be keyed by a morph type, such as [\'post\' => PostAttributes::class].',
        ];
        yield 'an entry keyed by an empty type' => [
            ['subjects' => ['' => RecordingSubjectAttributes::class]],
            self::ATTRIBUTES . '.subjects',
            'each entry must be keyed by a morph type, such as [\'post\' => PostAttributes::class].',
        ];
        yield 'a class that does not exist' => [
            ['resources' => ['post' => 'App\Missing']],
            self::ATTRIBUTES . '.resources.post',
            'expected the name of a class implementing ' . ResourceAttributeProvider::class . ', got \'App\Missing\'.',
        ];
        yield 'a class that is not a provider' => [
            ['subjects' => ['user' => StubIdentity::class]],
            self::ATTRIBUTES . '.subjects.user',
            'expected the name of a class implementing ' . SubjectAttributeProvider::class . ', got \'' . StubIdentity::class . '\'.',
        ];
        yield 'a resource provider registered for subjects' => [
            ['subjects' => ['user' => RecordingResourceAttributes::class]],
            self::ATTRIBUTES . '.subjects.user',
            'expected the name of a class implementing ' . SubjectAttributeProvider::class . ', got \'' . RecordingResourceAttributes::class . '\'.',
        ];
        yield 'an entry that is not a string' => [
            ['resources' => ['post' => 42]],
            self::ATTRIBUTES . '.resources.post',
            'expected the name of a class implementing ' . ResourceAttributeProvider::class . ', got int.',
        ];
        yield 'two providers declaring one key with different types' => [
            ['resources' => ['post' => RecordingResourceAttributes::class, 'page' => ConflictingResourceAttributes::class]],
            self::ATTRIBUTES,
            'Attribute provider ' . ConflictingResourceAttributes::class . ' declares \'resource.status\' as number, but another provider declares it as string.',
        ];
    }

    /**
     * An `attributes` config that does not register providers of the right kind
     * by morph type, or whose providers' declarations clash, is refused with
     * the key and the reason.
     *
     * @param  mixed  $config
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidConfigs')]
    public function testRefusesAnInvalidAttributesConfig(mixed $config, string $key, string $reason): void
    {
        try {
            AttributeConfigValidator::validate($config, $this->container());
            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }

    /**
     * Provide declarations a provider may not make, with the reason.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: string}>
     */
    public static function invalidDeclarations(): iterable
    {
        yield 'a built-in' => [
            ['id' => 'string'],
            'Attribute provider ' . ConflictingResourceAttributes::class . ' declares \'resource.id\', which is a built-in or under one; ' . self::BUILT_INS,
        ];
        yield 'a key under a built-in' => [
            ['tenant.name' => 'string'],
            'Attribute provider ' . ConflictingResourceAttributes::class . ' declares \'resource.tenant.name\', which is a built-in or under one; ' . self::BUILT_INS,
        ];
        yield 'an unknown type' => [
            ['status' => 'text'],
            'Context key \'resource.status\' has an unknown type \'text\'; use one of string, number, bool, time, ip, list.',
        ];
        yield 'a type that is not a name' => [
            ['status' => 5],
            'provider \'' . ConflictingResourceAttributes::class . '\' ' . self::TYPE_MAP,
        ];
        yield 'a path that is not a string' => [
            ['string'],
            'provider \'' . ConflictingResourceAttributes::class . '\' ' . self::TYPE_MAP,
        ];
        yield 'a key under another it declares' => [
            ['owner' => 'string', 'owner.id' => 'string'],
            'Attribute provider ' . ConflictingResourceAttributes::class . ' declares \'resource.owner.id\' under \'resource.owner\', which it also declares;'
                . ' declare the keys under \'resource.owner\' alone.',
        ];
        yield 'a malformed path' => [
            ['status..code' => 'string'],
            'Context key \'resource.status..code\' must be a namespace and one or more \'.\'-separated segments of letters, digits, \'_\' and \'-\','
                . ' and at most 128 characters.',
        ];
    }

    /**
     * A provider declaring a built-in, a key under one, an unknown type, a
     * value that is not a type, a key under another it declares, or a malformed
     * path is refused at boot.
     *
     * @param  array<array-key, mixed>  $declared
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidDeclarations')]
    public function testRefusesAnInvalidDeclaration(array $declared, string $reason): void
    {
        $this->container()->instance(ConflictingResourceAttributes::class, new ConflictingResourceAttributes($declared));

        try {
            AttributeConfigValidator::validate(['resources' => ['post' => ConflictingResourceAttributes::class]], $this->container());
            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame(self::ATTRIBUTES, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }

    /**
     * A provider the container cannot resolve, or resolves as something that
     * does not implement its contract, is refused, with the reason it could not
     * be resolved.
     *
     * @return void
     */
    public function testRefusesAProviderTheContainerCannotResolve(): void
    {
        $this->container()->bind(RecordingResourceAttributes::class, 'App\Missing');
        $this->container()->bind(RecordingSubjectAttributes::class, static fn (): RecordingResourceAttributes => new RecordingResourceAttributes);

        $prefix  = 'a provider could not be resolved from the container: ';
        $reasons = [];

        foreach (['resources' => RecordingResourceAttributes::class, 'subjects' => RecordingSubjectAttributes::class] as $key => $class) {
            try {
                AttributeConfigValidator::validate([$key => ['post' => $class]], $this->container());

                self::fail("A provider of {$key} that cannot be resolved is refused.");
            } catch (InvalidAuthorizationConfigException $exception) {
                $reasons[$key] = $exception->getReason();

                self::assertSame(self::ATTRIBUTES, $exception->getConfigKey());
                self::assertStringStartsWith($prefix, $exception->getReason());
            }
        }

        self::assertStringContainsString('App\Missing', $reasons['resources']);
        self::assertSame(
            $prefix . 'Attribute provider \'' . RecordingSubjectAttributes::class . '\' does not implement ' . SubjectAttributeProvider::class . '.',
            $reasons['subjects'],
        );
    }

    /**
     * The boot-time validation of the whole configuration validates
     * `authorization.attributes` too.
     *
     * @return void
     */
    public function testTheConfigValidatorValidatesTheAttributes(): void
    {
        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessage('Invalid authorization config at \'authorization.attributes.resources.post\'');

        /** @var array<string, mixed> $config */
        $config = (array) $this->container()->make('config')->get('authorization');

        ConfigValidator::validate(['attributes' => ['resources' => ['post' => 'App\Missing']]] + $config, $this->container());
    }

    /**
     * Each entry is checked on its own without building its provider, each
     * refusal structured; the declarations are checked by building them.
     *
     * @return void
     */
    public function testEachEntryIsCheckedWithoutBuilding(): void
    {
        $app      = $this->container();
        $expected = 'a morph type mapped to the name of a class implementing ' . ResourceAttributeProvider::class;

        AttributeConfigValidator::provider('resources', 'post', RecordingResourceAttributes::class, ResourceAttributeProvider::class);

        self::assertFalse($app->resolved(RecordingResourceAttributes::class));
        self::assertSame(
            ['authorization.attributes.resources', 'invalid_value', $expected, 'string'],
            self::refusedSetting(static fn () => AttributeConfigValidator::provider('resources', '', 'X', ResourceAttributeProvider::class)),
        );
        self::assertSame(
            ['authorization.attributes.resources.post', 'unknown_class', $expected, 'string'],
            self::refusedSetting(static fn () => AttributeConfigValidator::provider('resources', 'post', 'Missing\X', ResourceAttributeProvider::class)),
        );
        self::assertSame('invalid_type', self::refusedSetting(static fn () => AttributeConfigValidator::provider('resources', 'post', 3, ResourceAttributeProvider::class))[1]);
        self::assertSame(
            'not_implemented',
            self::refusedSetting(static fn () => AttributeConfigValidator::provider('subjects', 'user', \stdClass::class, SubjectAttributeProvider::class))[1],
        );

        AttributeConfigValidator::declarations(['post' => RecordingResourceAttributes::class], [], $app);

        self::assertSame('invalid_value', self::refusedSetting(static fn () => AttributeConfigValidator::declarations(
            ['post' => RecordingResourceAttributes::class, 'page' => ConflictingResourceAttributes::class],
            [],
            $app,
        ))[1]);
    }
}
