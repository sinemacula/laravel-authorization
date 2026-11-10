<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;

/**
 * Unit tests for reading what a container holds for a contract at the time the
 * report reads it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CurrentBinding::class)]
final class CurrentBindingTest extends TestCase
{
    /**
     * Each kind of binding gives its lifetime, an instance handed over is what
     * supplies the contract, and nothing bound gives none.
     *
     * @return void
     */
    public function testEachKindOfBindingIsRead(): void
    {
        $container = new Container;
        $instance  = new \stdClass;

        $container->bind('transient', \stdClass::class);
        $container->singleton('singleton', \stdClass::class);
        $container->scoped('scoped', \stdClass::class);
        $container->instance('instance', $instance);

        self::assertSame(Lifetime::TRANSIENT, CurrentBinding::of($container, 'transient')->lifetime);
        self::assertSame(Lifetime::SINGLETON, CurrentBinding::of($container, 'singleton')->lifetime);
        self::assertSame(Lifetime::SCOPED, CurrentBinding::of($container, 'scoped')->lifetime);
        self::assertSame(Lifetime::INSTANCE, CurrentBinding::of($container, 'instance')->lifetime);
        self::assertSame($instance, CurrentBinding::of($container, 'instance')->supplier());
        self::assertNull(CurrentBinding::of($container, 'nothing')->lifetime);
        self::assertNull(CurrentBinding::of($container, 'nothing')->supplier());
    }

    /**
     * What a singleton built is held as an instance, but is not one handed
     * over: the binding still supplies the contract, and it was resolved
     * before; an instance handed over a transient binding supplies it.
     *
     * @return void
     */
    public function testWhatASingletonBuiltIsNotAnInstanceHandedOver(): void
    {
        $container = new Container;
        $handed    = new \stdClass;

        $container->singleton('singleton', \stdClass::class);

        $built = $container->make('singleton');

        $container->bind('transient', \stdClass::class);
        $container->instance('transient', $handed);

        $singleton = CurrentBinding::of($container, 'singleton');
        $transient = CurrentBinding::of($container, 'transient');

        self::assertSame($built, $singleton->instance);
        self::assertSame($singleton->concrete, $singleton->supplier());
        self::assertSame(Lifetime::SINGLETON, $singleton->lifetime);
        self::assertTrue($singleton->previouslyResolved);
        self::assertSame($handed, $transient->supplier());
        self::assertSame(Lifetime::INSTANCE, $transient->lifetime);
        self::assertFalse(CurrentBinding::of($container, 'unmade')->previouslyResolved);
    }

    /**
     * An instance handed over a singleton or a scoped binding never resolved is
     * what the contract resolves to, so it supplies the contract, while a
     * scoped binding whose instance was forgotten supplies it again.
     *
     * @return void
     */
    public function testAnInstanceHandedOverASharedBindingSuppliesIt(): void
    {
        $container = new Container;
        $handed    = new \ArrayObject;

        $container->singleton('singleton', \stdClass::class);
        $container->instance('singleton', $handed);
        $container->scoped('scoped', \stdClass::class);
        $container->instance('scoped', $handed);

        foreach (['singleton', 'scoped'] as $key) {
            $binding = CurrentBinding::of($container, $key);

            self::assertSame($handed, $binding->supplier(), $key);
            self::assertSame(Lifetime::INSTANCE, $binding->lifetime, $key);
            self::assertSame(\get_class($container->make($key)), \get_class($binding->instance ?? new \stdClass), $key);
        }

        $container->make('scoped');
        $container->forgetScopedInstances();

        self::assertSame(Lifetime::SCOPED, CurrentBinding::of($container, 'scoped')->lifetime);
        self::assertNull(CurrentBinding::of($container, 'scoped')->instance);
    }

    /**
     * An instance handed over and never resolved was not resolved before,
     * although Laravel's `resolved()` says it was.
     *
     * @return void
     */
    public function testAnInstanceNeverResolvedWasNotResolvedBefore(): void
    {
        $container = new Container;

        $container->instance('instance', new \stdClass);

        self::assertTrue($container->resolved('instance'));
        self::assertFalse(CurrentBinding::of($container, 'instance')->previouslyResolved);
    }

    /**
     * An alias and a deferred provider not loaded yet are read, and nothing is
     * loaded to read them.
     *
     * @return void
     */
    public function testAliasesAndDeferredProvidersAreRead(): void
    {
        $app = new Application(\dirname(__DIR__, 3));

        $app->alias('target', 'alias');
        $app->addDeferredServices(['deferred' => 'Acme\DeferredProvider']);

        self::assertSame('target', CurrentBinding::of($app, 'alias')->alias);
        self::assertSame('Acme\DeferredProvider', CurrentBinding::of($app, 'deferred')->deferredProvider);
        self::assertNull(CurrentBinding::of($app, 'alias')->deferredProvider);
        self::assertTrue($app->isDeferredService('deferred'));

        Container::setInstance(null);
    }
}
