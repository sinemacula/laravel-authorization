<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Enums\MutationOperation;

/**
 * Unit tests for `MutationOperation`, the operation identifier of each change
 * event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MutationOperation::class)]
final class MutationOperationTest extends TestCase
{
    /**
     * Every change event returns a case's value, and every case is returned by
     * exactly one change event.
     *
     * @return void
     */
    public function testEveryChangeEventReturnsItsOwnCase(): void
    {
        $returned = [];

        foreach (self::mutations() as $class) {
            $operation = (new \ReflectionClass($class))->newInstanceWithoutConstructor()->operation();

            self::assertNotNull(MutationOperation::tryFrom($operation), "{$class} returns {$operation}, which is no case.");

            $returned[$class] = $operation;
        }

        $values = \array_map(static fn (MutationOperation $case): string => $case->value, MutationOperation::cases());

        self::assertCount(37, $returned);
        self::assertEqualsCanonicalizing($values, \array_values($returned));
    }

    /**
     * The values are unique.
     *
     * @return void
     */
    public function testTheValuesAreUnique(): void
    {
        $values = \array_map(static fn (MutationOperation $case): string => $case->value, MutationOperation::cases());

        self::assertSame($values, \array_values(\array_unique($values)));
    }

    /**
     * The values are the strings the events have always returned.
     *
     * @return void
     */
    public function testTheValuesAreStable(): void
    {
        self::assertSame('identity.role.assigned', MutationOperation::IDENTITY_ROLE_ASSIGNED->value);
        self::assertSame('identity.role.expiry_changed', MutationOperation::IDENTITY_ROLE_EXPIRY_CHANGED->value);
        self::assertSame('identity.break_glass.activated', MutationOperation::IDENTITY_BREAK_GLASS_ACTIVATED->value);
        self::assertSame('permission.deleted', MutationOperation::PERMISSION_DELETED->value);
        self::assertSame('resource.policy.detached', MutationOperation::RESOURCE_POLICY_DETACHED->value);
        self::assertSame('guardrail.set', MutationOperation::GUARDRAIL_SET->value);
        self::assertSame('role.exclusion.removed', MutationOperation::ROLE_EXCLUSION_REMOVED->value);
    }

    /**
     * Return every concrete change event class under `src/Events`.
     *
     * @return list<class-string<\SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation>>
     */
    private static function mutations(): array
    {
        $root    = \dirname(__DIR__, 3) . '/src/Events';
        $files   = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
        $classes = [];

        foreach ($files as $file) {
            \assert($file instanceof \SplFileInfo);

            $class = 'SineMacula\Laravel\Authorization\Events\\' . \str_replace('/', '\\', \substr($file->getPathname(), \strlen($root) + 1, -4));

            if (!\is_subclass_of($class, AuthorizationMutation::class) || (new \ReflectionClass($class))->isAbstract()) {
                continue;
            }

            $classes[] = $class;
        }

        return $classes;
    }
}
