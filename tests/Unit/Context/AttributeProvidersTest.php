<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Context\AttributeProviders;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\ConflictingResourceAttributes;
use Tests\Feature\Stubs\FailingResourceAttributes;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\Feature\Stubs\RecordingSubjectAttributes;

/**
 * Unit tests for `AttributeProviders`, the subject and resource attribute
 * providers registered by morph type.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AttributeProviders::class)]
final class AttributeProvidersTest extends TestCase
{
    /** @var \Illuminate\Container\Container The container the providers are resolved from. */
    private Container $container;

    /** @var \Tests\Feature\Stubs\RecordingResourceAttributes The provider of `post` resources. */
    private RecordingResourceAttributes $posts;

    /** @var \Tests\Feature\Stubs\RecordingSubjectAttributes The provider of `user` subjects. */
    private RecordingSubjectAttributes $users;

    /**
     * Set up the container with a provider of each kind.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
        $this->posts     = new RecordingResourceAttributes;
        $this->users     = new RecordingSubjectAttributes;

        $this->container->instance(RecordingResourceAttributes::class, $this->posts);
        $this->container->instance(RecordingSubjectAttributes::class, $this->users);
    }

    /**
     * The declarations are keyed by namespace, then by the provider's class,
     * each as the provider declares it; a class registered for two types is
     * declared once.
     *
     * @return void
     */
    public function testDeclarationsAreKeyedByNamespaceAndClass(): void
    {
        $providers = new AttributeProviders(
            $this->container,
            ['post' => RecordingResourceAttributes::class, 'page' => RecordingResourceAttributes::class],
            ['user' => RecordingSubjectAttributes::class],
        );

        self::assertSame([
            'resource' => [RecordingResourceAttributes::class => ['status' => 'string', 'owner.id' => 'string']],
            'subject'  => [RecordingSubjectAttributes::class => ['department' => 'string']],
        ], $providers->declarations());
        self::assertSame([], (new AttributeProviders($this->container))->declarations());
    }

    /**
     * A record of a type with a provider has the attributes the provider
     * declares, nested as given, and none it does not declare; the provider is
     * given the record and the model the check was given.
     *
     * @return void
     */
    public function testARecordHasItsProvidersDeclaredAttributesOnly(): void
    {
        $model     = new class extends Model {};
        $reference = ResourceReference::record('post', '42', null, $model);

        $pair = ResourceReference::record('post', '43');

        self::assertSame(['status' => 'draft', 'owner' => ['id' => '7']], $this->providers()->resourceValues($reference));

        $this->providers()->resourceValues($pair);

        self::assertSame([[$reference, $model], [$pair, null]], $this->posts->calls);
    }

    /**
     * A type alone, an opaque identifier and a record of a type with no
     * provider have no attributes, and the provider is never asked.
     *
     * @return void
     */
    public function testOnlyARecordOfARegisteredTypeIsGivenToAProvider(): void
    {
        $providers = $this->providers();

        self::assertSame([], $providers->resourceValues(ResourceReference::type('post')));
        self::assertSame([], $providers->resourceValues(new ResourceReference('post:42')));
        self::assertSame([], $providers->resourceValues(ResourceReference::record('comment', '42')));
        self::assertSame([], $this->posts->calls);
    }

    /**
     * A subject of a type with a provider has the attributes the provider
     * declares, and one of another type has none, its provider never asked.
     *
     * @return void
     */
    public function testASubjectHasItsProvidersDeclaredAttributesOnly(): void
    {
        $subject = new \stdClass;

        self::assertSame(['department' => 'sales'], $this->providers()->subjectValues($subject, 'user'));
        self::assertSame([$subject], $this->users->calls);
        self::assertSame([], $this->providers()->subjectValues($subject, 'admin'));
        self::assertCount(1, $this->users->calls);
    }

    /**
     * Only the declared paths are exposed: a declared key the provider leaves
     * out, or one under a value that is not an array, is missing, a declared
     * key whose value is null stays present, and every key the provider does
     * not declare, even one beside a declared key, is dropped.
     *
     * @return void
     */
    public function testExposesOnlyTheDeclaredPaths(): void
    {
        $values = $this->valuesOf(
            ['owner.id' => 'string', 'owner.team' => 'string', 'status.code' => 'string', 'tags' => 'list', 'missing' => 'string'],
            ['owner' => ['id' => '7', 'team' => null, 'email' => 'x'], 'status' => 'draft', 'tags' => ['a', 'b'], 'extra' => 1],
        );

        self::assertSame(['owner' => ['id' => '7', 'team' => null], 'tags' => ['a', 'b']], $values);

        $context = new CheckContext(['resource' => $values]);

        self::assertSame([true, null], $context->lookup('resource.owner.team'));
        self::assertSame([false, null], $context->lookup('resource.owner.email'));
    }

    /**
     * A declared key whose value is an array is exposed only as a list of
     * scalars and nulls declared as a `list`: a map, a list holding an array
     * and a list under another type each stay present with a placeholder
     * nothing can be read through, so none of the keys under it is exposed, a
     * test of the key is undecidable and `${…}` leaves it unresolved.
     *
     * @return void
     */
    public function testADeclaredArrayIsExposedOnlyAsAListOfScalars(): void
    {
        $values = $this->valuesOf(
            ['owner' => 'string', 'team' => 'list', 'tags' => ContextKeyType::LIST, 'groups' => 'list', 'codes' => 'string', 'flags' => 'list'],
            [
                'owner'  => ['id' => '7', 'secret' => 'S'],
                'team'   => ['id' => '8', 'secret' => 'T'],
                'tags'   => ['a', null, 1, true],
                'groups' => [['id' => '9', 'secret' => 'G']],
                'codes'  => ['a', 'b'],
                'flags'  => [1 => 'a'],
            ],
        );

        self::assertSame(['a', null, 1, true], $values['tags']);

        $context      = new CheckContext(['resource' => $values]);
        $interpolator = new ContextInterpolator;

        foreach (['owner', 'team', 'groups', 'codes', 'flags'] as $key) {
            [$isPresent, $value] = $context->lookup("resource.{$key}");

            self::assertTrue($isPresent, "resource.{$key} stays present.");
            self::assertIsObject($value, "resource.{$key} cannot be read through.");
            self::assertSame(MatchOutcome::UNDECIDABLE, ConditionEvaluator::evaluate('starts_with', 'a', $value)->outcome);
            self::assertNull($interpolator->interpolate("\${resource.{$key}}", $context));
        }

        foreach (['owner.id', 'owner.secret', 'team.secret', 'groups.0', 'groups.0.secret', 'codes.0', 'flags.1'] as $path) {
            self::assertSame([false, null], $context->lookup("resource.{$path}"), "resource.{$path} is never exposed.");
            self::assertNull($interpolator->interpolate("\${resource.{$path}}", $context));
        }
    }

    /**
     * A provider is resolved from the container once, however many checks ask
     * it, and asked again for each.
     *
     * @return void
     */
    public function testAProviderIsResolvedOnce(): void
    {
        $resolved = 0;

        $this->container->bind(RecordingResourceAttributes::class, function () use (&$resolved): RecordingResourceAttributes {
            $resolved++;

            return $this->posts;
        });

        $providers = $this->providers();

        $providers->resourceValues(ResourceReference::record('post', '1'));
        $providers->resourceValues(ResourceReference::record('post', '2'));
        $providers->declarations();

        self::assertSame(1, $resolved);
        self::assertCount(2, $this->posts->calls);
    }

    /**
     * A provider that throws aborts with `AttributeProviderFailed`, naming the
     * provider and the namespace and keeping the failure as the previous
     * exception, without copying its message.
     *
     * @return void
     */
    public function testAProviderThatThrowsFailsWithTheDedicatedException(): void
    {
        $providers = new AttributeProviders($this->container, ['post' => FailingResourceAttributes::class]);

        try {
            $providers->resourceValues(ResourceReference::record('post', '1'));

            self::fail('A provider that throws fails the read.');
        } catch (AttributeProviderFailed $exception) {
            self::assertSame(FailingResourceAttributes::class, $exception->getProvider());
            self::assertSame('resource', $exception->getNamespace());
            self::assertInstanceOf(\RuntimeException::class, $exception->getPrevious());
            self::assertSame(FailingResourceAttributes::MESSAGE, $exception->getPrevious()->getMessage());
            self::assertStringNotContainsString('owner@example.com', $exception->getMessage());
        }
    }

    /**
     * A provider that cannot be resolved, or that does not implement its
     * namespace's contract, fails the read with `AttributeProviderFailed`, and
     * fails reading the declarations outright.
     *
     * @return void
     */
    public function testAProviderThatCannotBeResolvedFails(): void
    {
        $this->container->instance('not-a-provider', new \stdClass);

        $providers = new AttributeProviders($this->container, ['post' => 'App\Missing'], ['user' => 'not-a-provider']);

        $reads = [
            'resource' => static fn (): array => $providers->resourceValues(ResourceReference::record('post', '1')),
            'subject'  => static fn (): array => $providers->subjectValues(new \stdClass, 'user'),
        ];

        foreach ($reads as $namespace => $read) {
            try {
                $read();

                self::fail('A provider that cannot be resolved fails the read.');
            } catch (AttributeProviderFailed $exception) {
                self::assertSame($namespace, $exception->getNamespace());
            }
        }

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Attribute provider \'not-a-provider\' does not implement ' . SubjectAttributeProvider::class . '.');

        (new AttributeProviders($this->container, [], ['user' => 'not-a-provider']))->declarations();
    }

    /**
     * A resource provider registered as a subject's, or the other way round,
     * does not implement the contract its namespace calls for.
     *
     * @return void
     */
    public function testAProviderOfTheWrongKindIsRefused(): void
    {
        $this->container->instance(ConflictingResourceAttributes::class, new ConflictingResourceAttributes);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Attribute provider \'' . ConflictingResourceAttributes::class . '\' does not implement ' . SubjectAttributeProvider::class . '.');

        (new AttributeProviders($this->container, [], ['user' => ConflictingResourceAttributes::class]))->declarations();
    }

    /**
     * The providers of `authorization.attributes` are those the configuration
     * registers.
     *
     * @return void
     */
    public function testFromConfigReadsTheConfiguredProviders(): void
    {
        $this->container->instance('config', new Repository(['authorization' => ['attributes' => [
            'resources' => ['post' => RecordingResourceAttributes::class],
            'subjects'  => ['user' => RecordingSubjectAttributes::class],
        ]]]));

        $providers = AttributeProviders::fromConfig($this->container);

        self::assertSame(['status' => 'draft', 'owner' => ['id' => '7']], $providers->resourceValues(ResourceReference::record('post', '1')));
        self::assertSame(['department' => 'sales'], $providers->subjectValues(new \stdClass, 'user'));

        $this->container->instance('config', new Repository);

        self::assertSame([], AttributeProviders::fromConfig($this->container)->declarations());
    }

    /**
     * A null `resources` or `subjects`, which the configuration validator
     * accepts, registers no provider.
     *
     * @return void
     */
    public function testFromConfigTakesANullListAsNoProviders(): void
    {
        $this->container->instance('config', new Repository(['authorization' => ['attributes' => ['resources' => null, 'subjects' => null]]]));

        $providers = AttributeProviders::fromConfig($this->container);

        self::assertSame([], $providers->declarations());
        self::assertSame([], $providers->resourceValues(ResourceReference::record('post', '1')));
        self::assertSame([], $providers->subjectValues(new \stdClass, 'user'));
    }

    /**
     * The class of the subject attribute provider registered for a morph type
     * is named, and a type with none has none.
     *
     * @return void
     */
    public function testNamesTheSubjectProviderOfAType(): void
    {
        $providers = new AttributeProviders(new Container, ['post' => RecordingResourceAttributes::class], ['user' => RecordingSubjectAttributes::class]);

        self::assertSame(RecordingSubjectAttributes::class, $providers->subjectProviderClass('user'));
        self::assertNull($providers->subjectProviderClass('post'));
        self::assertNull($providers->subjectProviderClass('machine'));
    }

    /**
     * Return the values a `post` provider declaring the attributes exposes for
     * a record when it returns the given values.
     *
     * @param  array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>  $attributes
     * @param  array<string, mixed>  $values
     * @return array<string, mixed>
     */
    private function valuesOf(array $attributes, array $values): array
    {
        $provider = new class ($attributes, $values) implements ResourceAttributeProvider {
            /**
             * Create a new provider declaring the attributes and returning the
             * values.
             *
             * @param  array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>  $attributes
             * @param  array<string, mixed>  $values
             */
            public function __construct(

                /** The attributes the provider declares. */
                private readonly array $attributes,

                /** The values the provider returns. */
                private readonly array $values,
            ) {}

            /**
             * Return the attributes the provider declares.
             *
             * @return array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>
             */
            #[\Override]
            public function attributes(): array
            {
                return $this->attributes;
            }

            /**
             * Return the record's attributes.
             *
             * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
             * @param  \Illuminate\Database\Eloquent\Model|null  $model
             * @return array<string, mixed>
             */
            #[\Override]
            public function values(ResourceReference $resource, ?Model $model): array
            {
                return $this->values;
            }
        };

        $this->container->instance('provider', $provider);

        return (new AttributeProviders($this->container, ['post' => 'provider']))->resourceValues(ResourceReference::record('post', '1'));
    }

    /**
     * Return the providers of `post` resources and `user` subjects.
     *
     * @return \SineMacula\Laravel\Authorization\Context\AttributeProviders
     */
    private function providers(): AttributeProviders
    {
        return new AttributeProviders($this->container, ['post' => RecordingResourceAttributes::class], ['user' => RecordingSubjectAttributes::class]);
    }
}
