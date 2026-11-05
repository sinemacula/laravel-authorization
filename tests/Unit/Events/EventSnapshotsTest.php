<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Walks every event class the package ships and pins that each implements the
 * `AuthorizationEvent` marker, and that every change event is a final readonly
 * snapshot of plain values: scalars, arrays of them or of references, the
 * package's value objects and dates, never a model or any other object.
 *
 * The decision events keep the principal, the context and the result as they
 * were evaluated until their payload is redesigned, so only the marker is
 * checked for them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class EventSnapshotsTest extends TestCase
{
    /** @var list<class-string> The value objects a change event may carry. */
    private const array VALUE_OBJECTS = [Operation::class, Reference::class, GrantScope::class, DocumentDigest::class];

    /** @var list<class-string> The decision events, which carry what they evaluated. */
    private const array DECISION_EVENTS = [DecisionEvaluated::class, AuthorizationFailed::class];

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
        self::assertCount(23, $names);
    }

    /**
     * Every event class under `src/Events`.
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
     * Every change event is a final readonly snapshot whose constructor takes
     * only plain values.
     *
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('events')]
    public function testCarriesOnlyPlainValues(string $class): void
    {
        if (\in_array($class, self::DECISION_EVENTS, true)) {
            self::assertTrue((new \ReflectionClass($class))->isFinal());

            return;
        }

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
     * Assert the class is final and readonly, and that each constructor
     * parameter is a scalar, an array of plain values, one of the package's
     * value objects or a date.
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

            self::assertArrayHoldsOnlyReferences($class, $constructor, $parameter->getName());
        }
    }

    /**
     * Assert the docblock type of an array parameter names no class other than
     * `Reference`.
     *
     * @param  class-string  $class
     * @param  \ReflectionMethod  $constructor
     * @param  string  $name
     * @return void
     */
    private static function assertArrayHoldsOnlyReferences(string $class, \ReflectionMethod $constructor, string $name): void
    {
        $matched = \preg_match('/@param\s+(.+?)\s+\$' . $name . '\b/', (string) $constructor->getDocComment(), $match);

        self::assertSame(1, $matched, "{$class}::\${$name} documents no element type.");

        \preg_match_all('/\\\?[A-Z][A-Za-z]*(?:\\\[A-Za-z]+)+/', $match[1], $classes);

        foreach ($classes[0] as $named) {
            self::assertSame(Reference::class, \ltrim($named, '\\'), "{$class}::\${$name} holds {$named}.");
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
            || \is_a($type, \DateTimeInterface::class, true);
    }
}
