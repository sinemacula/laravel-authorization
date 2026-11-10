<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;

/**
 * Unit tests for where a sibling package declares the adapters it binds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Declarations::class)]
final class DeclarationsTest extends TestCase
{
    /**
     * Each container holds its own declarations, the same each time they are
     * asked for, whichever package asks first.
     *
     * @return void
     */
    public function testEachContainerHoldsItsOwn(): void
    {
        $container = new Container;
        $other     = new Container;

        self::assertSame(Declarations::of($container), Declarations::of($container));
        self::assertNotSame(Declarations::of($container), Declarations::of($other));
        self::assertSame(Declarations::of($container), $container->make(Declarations::class));
    }

    /**
     * An adapter and a factory are declared as data, each in place of an
     * earlier declaration of its contract, nothing they name being loaded.
     *
     * @return void
     */
    public function testAdaptersAndFactoriesAreDeclared(): void
    {
        $declarations = new Declarations;
        $binding      = static fn (): object => new \stdClass;

        $declarations->adapter('First', 'acme/one', 'Not\A\Loaded\Class', Lifetime::SCOPED, $binding);
        $declarations->factory('Second', 'acme/two', ['Not\Loaded\A', 'Not\Loaded\B'], 'per tenant', Lifetime::TRANSIENT);
        $declarations->adapter('Second', 'acme/three', 'Not\Loaded\C', Lifetime::SINGLETON);

        $first  = $declarations->for('First');
        $second = $declarations->for('Second');

        self::assertNotNull($first);
        self::assertNotNull($second);
        self::assertSame(['First', 'Second'], \array_keys($declarations->all()));
        self::assertSame(['Not\A\Loaded\Class'], $first->classes);
        self::assertSame($binding, $first->binding);
        self::assertSame('acme/three', $second->owner);
        self::assertNull($declarations->for('Third'));
        self::assertFalse(\class_exists('Not\A\Loaded\Class', false));
    }
}
