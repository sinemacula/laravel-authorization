<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Walks every event class the package ships and pins that each implements the
 * `AuthorizationEvent` marker, and that every event, the decision events
 * included, is a final readonly snapshot of plain values: scalars, backed
 * enums, arrays of them or of the package's value objects, those value objects
 * and dates, never a model or any other object (AUTHZ-15.3, AUTHZ-15.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class EventSnapshotsTest extends TestCase
{
    /** @var list<string> The events that report a decision or an override, not a change to stored records. */
    private const array NOT_MUTATIONS = ['DecisionEvaluated', 'AuthorizationFailed', 'SystemOverrideUsed'];

    /** @var list<class-string> The value objects an event may carry. */
    private const array VALUE_OBJECTS = [Operation::class, Reference::class, GrantScope::class, DocumentDigest::class, StatementReference::class];

    /**
     * The walk finds every event, decision and change events alike.
     *
     * @return void
     */
    public function testFindsEveryEvent(): void
    {
        $names = \array_keys(\iterator_to_array(self::events()));

        self::assertContains('DecisionEvaluated', $names);
        self::assertContains('SystemOverrideUsed', $names);
        self::assertContains('Identity/RoleAssigned', $names);
        self::assertContains('Role/PermissionGranted', $names);
        self::assertContains('Identity/BoundarySet', $names);
        self::assertContains('Identity/BoundaryRemoved', $names);
        self::assertContains('Guardrail/GuardrailSet', $names);
        self::assertContains('Guardrail/GuardrailRemoved', $names);
        self::assertCount(34, $names);
    }

    /**
     * Every event class under `src/Events`, leaving out an abstract class that
     * events of one kind share, which is never dispatched itself, and a trait
     * that gives events of one kind their audit accessors.
     *
     * @return iterable<string, array{class-string}>
     */
    public static function events(): iterable
    {
        $root  = \dirname(__DIR__, 3) . '/src/Events';
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));

        foreach ($files as $file) {
            \assert($file instanceof \SplFileInfo);

            $relative = \substr($file->getPathname(), \strlen($root) + 1, -4);

            /** @var class-string $class */
            $class = 'SineMacula\Laravel\Authorization\Events\\' . \str_replace('/', '\\', $relative);

            $reflection = new \ReflectionClass($class);

            if ($reflection->isAbstract() || $reflection->isTrait()) {
                continue;
            }

            yield $relative => [$class];
        }
    }

    /**
     * Every event implements the marker.
     *
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('events')]
    public function testImplementsTheMarker(string $class): void
    {
        self::assertTrue(\is_subclass_of($class, AuthorizationEvent::class), "{$class} does not implement AuthorizationEvent.");
    }

    /**
     * Every event, a decision event included, is a final readonly snapshot
     * whose constructor takes only plain values.
     *
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('events')]
    public function testCarriesOnlyPlainValues(string $class): void
    {
        self::assertSnapshot($class);
    }

    /**
     * Every change event under `Events\Identity` names its grantee.
     *
     * @return iterable<string, array{class-string}>
     */
    public static function identityEvents(): iterable
    {
        foreach (self::events() as $name => [$class]) {
            if (!\str_starts_with($name, 'Identity/')) {
                continue;
            }

            yield $name => [$class];
        }
    }

    /**
     * Every grant event implements `IdentityEvent` and names its grantee by
     * reference, as the cache listener reads it.
     *
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('identityEvents')]
    public function testNamesTheGrantee(string $class): void
    {
        $grantee = new \ReflectionProperty($class, 'grantee');

        self::assertTrue(\is_subclass_of($class, IdentityEvent::class));
        self::assertSame(Reference::class, (string) $grantee->getType());
    }

    /**
     * Every event but the decision events and the override event reports a
     * change to stored records, so implements `AuthorizationMutation`; those
     * three do not.
     *
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('events')]
    public function testEveryChangeEventIsAMutation(string $class): void
    {
        $name = (new \ReflectionClass($class))->getShortName();

        self::assertSame(!\in_array($name, self::NOT_MUTATIONS, true), \is_subclass_of($class, AuthorizationMutation::class), "{$class} is misclassified.");
    }

    /**
     * Every change event names its own operation identifier, dotted lower case
     * words, unique among them all.
     *
     * @return void
     */
    public function testOperationIdentifiersAreUnique(): void
    {
        $operations = [];

        foreach (self::mutations() as [$class]) {
            $operations[$class] = self::sample($class)->operation();

            self::assertMatchesRegularExpression('/^[a-z_]+(\.[a-z_]+)+$/', $operations[$class]);
        }

        self::assertCount(31, $operations);
        self::assertSame(\array_values($operations), \array_values(\array_unique($operations)));
    }

    /**
     * Every change event: every event but the decision events and the override
     * event.
     *
     * @return iterable<string, array{class-string<\SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation>}>
     */
    public static function mutations(): iterable
    {
        foreach (self::events() as $name => [$class]) {
            if (!\is_subclass_of($class, AuthorizationMutation::class)) {
                continue;
            }

            yield $name => [$class];
        }
    }

    /**
     * Every change event's details are serialisable, unchanged through a JSON
     * round trip, so they hold no object, and never include the operation.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation>  $class
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('mutations')]
    public function testAuditPropertiesAreFlatAndSerialisable(string $class): void
    {
        $properties = self::sample($class)->auditProperties();

        self::assertNotSame([], $properties);
        self::assertArrayNotHasKey('operation', $properties);
        self::assertSame($properties, \json_decode(\json_encode($properties, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR));
    }

    /**
     * No change event reports the IP address or the user agent of the call that
     * made it, though its operation carries them: neither through an accessor
     * nor in its details.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation>  $class
     * @return void
     */
    #[DataProvider('mutations')]
    public function testNoChangeEventReportsTheClient(string $class): void
    {
        $at       = new \DateTimeImmutable('2026-03-04T05:06:07Z');
        $event    = self::sample($class, new Operation('op-client', new Reference('principal', '5'), $at, false, null, null, [], '203.0.113.9', 'Browser/1.0'));
        $reported = [];

        foreach ((new \ReflectionClass(AuthorizationMutation::class))->getMethods() as $method) {
            $reported[$method->getName()] = (new \ReflectionMethod($event, $method->getName()))->invoke($event);
        }

        self::assertStringContainsString('203.0.113.9', \serialize($event));
        self::assertStringNotContainsString('203.0.113.9', \serialize($reported));
        self::assertStringNotContainsString('Browser/1.0', \serialize($reported));
    }

    /**
     * The value objects the events carry are snapshots of plain values too.
     *
     * @return void
     */
    public function testTheValueObjectsCarryOnlyPlainValues(): void
    {
        foreach (self::VALUE_OBJECTS as $class) {
            self::assertSnapshot($class);
        }
    }

    /**
     * Return an instance of the change event, made by the operation given or a
     * new one, each other parameter given a sample of its type.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation>  $class
     * @param  \SineMacula\Laravel\Authorization\Support\Operation|null  $operation
     * @return \SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation
     */
    private static function sample(string $class, ?Operation $operation = null): AuthorizationMutation
    {
        $arguments = [];

        foreach ((new \ReflectionMethod($class, '__construct'))->getParameters() as $parameter) {
            $arguments[] = $parameter->getName() === 'operation' && $operation !== null ? $operation : self::sampleOf($parameter);
        }

        return new $class(...$arguments);
    }

    /**
     * Return a sample of the parameter's type: a map of changes for `changes`,
     * a list of references for any other array.
     *
     * @param  \ReflectionParameter  $parameter
     * @return mixed
     */
    private static function sampleOf(\ReflectionParameter $parameter): mixed
    {
        $type    = $parameter->getType();
        $samples = [
            Operation::class          => Operation::begin(),
            Reference::class          => new Reference('record', 'sample'),
            GrantScope::class         => new GrantScope(new Reference('team', '7'), 'admin'),
            DocumentDigest::class     => new DocumentDigest(1, 'abc'),
            \DateTimeImmutable::class => new \DateTimeImmutable('2026-01-02T03:04:05Z'),
            'string'                  => 'sample',
            'bool'                    => true,
            'array'                   => [new Reference('record', 'listed')],
        ];

        self::assertInstanceOf(\ReflectionNamedType::class, $type);
        self::assertArrayHasKey($type->getName(), $samples, "\${$parameter->getName()} has no sample.");

        return $parameter->getName() === 'changes' ? ['before' => ['name' => 'a'], 'after' => ['name' => 'b']] : $samples[$type->getName()];
    }

    /**
     * Assert the class is final and readonly, and that each constructor
     * parameter is a scalar, a backed enum, an array of plain values, one of
     * the package's value objects or a date.
     *
     * @param  class-string  $class
     * @return void
     */
    private static function assertSnapshot(string $class): void
    {
        $reflection  = new \ReflectionClass($class);
        $constructor = $reflection->getConstructor();

        self::assertTrue($reflection->isFinal(), "{$class} is not final.");
        self::assertTrue($reflection->isReadOnly(), "{$class} is not readonly.");
        self::assertNotNull($constructor);

        foreach ($constructor->getParameters() as $parameter) {
            $type = $parameter->getType();

            self::assertInstanceOf(\ReflectionNamedType::class, $type, "{$class}::\${$parameter->getName()} has no single type.");
            self::assertTrue(self::isPlain($type->getName()), "{$class}::\${$parameter->getName()} is a {$type->getName()}.");

            if ($type->getName() !== 'array') {
                continue;
            }

            self::assertArrayHoldsOnlyValueObjects($class, $constructor, $parameter->getName());
        }
    }

    /**
     * Assert the docblock type of an array parameter names no class other than
     * the package's value objects.
     *
     * @param  class-string  $class
     * @param  \ReflectionMethod  $constructor
     * @param  string  $name
     * @return void
     */
    private static function assertArrayHoldsOnlyValueObjects(string $class, \ReflectionMethod $constructor, string $name): void
    {
        $matched = \preg_match('/@param\s+(.+?)\s+\$' . $name . '\b/', (string) $constructor->getDocComment(), $match);

        self::assertSame(1, $matched, "{$class}::\${$name} documents no element type.");

        \preg_match_all('/\\\?[A-Z][A-Za-z]*(?:\\\[A-Za-z]+)+/', $match[1], $classes);

        foreach ($classes[0] as $named) {
            self::assertContains(\ltrim($named, '\\'), self::VALUE_OBJECTS, "{$class}::\${$name} holds {$named}.");
        }
    }

    /**
     * Determine whether a parameter type is a plain value.
     *
     * @param  string  $type
     * @return bool
     */
    private static function isPlain(string $type): bool
    {
        return \in_array($type, ['string', 'int', 'float', 'bool', 'array'], true)
            || \in_array($type, self::VALUE_OBJECTS, true)
            || \is_subclass_of($type, \BackedEnum::class)
            || \is_a($type, \DateTimeInterface::class, true);
    }
}
