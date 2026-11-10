<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\ContainerState;

/**
 * Unit tests for reading what a container holds for an abstract without
 * building anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContainerState::class)]
final class ContainerStateTest extends TestCase
{
    /**
     * The binding's closure, whether it is shared or scoped, and an instance
     * handed over are read, and nothing is built.
     *
     * @return void
     */
    public function testBindingsAndInstancesAreRead(): void
    {
        $container = new Container;
        $instance  = new \stdClass;

        $container->bind('transient', \stdClass::class);
        $container->singleton('singleton', \stdClass::class);
        $container->scoped('scoped', \stdClass::class);
        $container->instance('instance', $instance);
        $container->instance('scalar', 'value');

        self::assertInstanceOf(\Closure::class, ContainerState::concrete($container, 'transient'));
        self::assertNull(ContainerState::concrete($container, 'instance'));
        self::assertFalse(ContainerState::isShared($container, 'transient'));
        self::assertTrue(ContainerState::isShared($container, 'singleton'));
        self::assertFalse(ContainerState::isScoped($container, 'singleton'));
        self::assertTrue(ContainerState::isScoped($container, 'scoped'));
        self::assertSame($instance, ContainerState::instance($container, 'instance'));
        self::assertNull(ContainerState::instance($container, 'scalar'));
        self::assertNull(ContainerState::instance($container, 'singleton'));
        self::assertFalse($container->resolved('singleton'));
    }

    /**
     * The extenders still pending are read in order through the alias, and the
     * alias is read; an abstract that is no alias has none.
     *
     * @return void
     */
    public function testExtendersAndAliasesAreRead(): void
    {
        $container = new Container;
        $first     = static fn (object $built): object => $built;
        $second    = static fn (object $built): object => $built;

        $container->bind('target', \stdClass::class);
        $container->alias('target', 'alias');
        $container->extend('target', $first);
        $container->extend('alias', $second);

        self::assertSame([$first, $second], ContainerState::extenders($container, 'alias'));
        self::assertSame([$first, $second], ContainerState::extenders($container, 'target'));
        self::assertSame('target', ContainerState::alias($container, 'alias'));
        self::assertNull(ContainerState::alias($container, 'target'));
        self::assertSame([], ContainerState::extenders($container, 'other'));
    }

    /**
     * Whether an abstract was resolved is read through its alias, and an
     * instance handed over and never resolved was not, although Laravel's own
     * `resolved()` says it was.
     *
     * @return void
     */
    public function testWhetherAnAbstractWasResolvedIsRead(): void
    {
        $container = new Container;

        $container->singleton('singleton', \stdClass::class);
        $container->alias('singleton', 'alias');
        $container->instance('instance', new \stdClass);

        self::assertFalse(ContainerState::wasResolved($container, 'alias'));

        $container->make('singleton');

        self::assertTrue(ContainerState::wasResolved($container, 'singleton'));
        self::assertTrue(ContainerState::wasResolved($container, 'alias'));
        self::assertTrue($container->resolved('instance'));
        self::assertFalse(ContainerState::wasResolved($container, 'instance'));
        self::assertFalse(ContainerState::wasResolved($container, 'other'));
    }

    /**
     * A container that is not Laravel's holds nothing that can be read.
     *
     * @return void
     */
    public function testAnotherContainerHoldsNothingReadable(): void
    {
        $container = self::createStub(ContainerContract::class);

        self::assertNull(ContainerState::concrete($container, 'a'));
        self::assertFalse(ContainerState::isShared($container, 'a'));
        self::assertNull(ContainerState::instance($container, 'a'));
        self::assertFalse(ContainerState::isScoped($container, 'a'));
        self::assertSame([], ContainerState::extenders($container, 'a'));
        self::assertNull(ContainerState::alias($container, 'a'));
        self::assertFalse(ContainerState::wasResolved($container, 'a'));
    }
}
