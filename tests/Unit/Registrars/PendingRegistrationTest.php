<?php

declare(strict_types = 1);

namespace Tests\Unit\Registrars;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Registrars\PendingRegistration;

/**
 * Unit tests for the registration steps the package leaves to the application's
 * boot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingRegistration::class)]
final class PendingRegistrationTest extends TestCase
{
    /**
     * Each container holds its own steps, the same each time they are asked
     * for; a container holding none is found to hold none, and asking for them
     * holds none first.
     *
     * @return void
     */
    public function testEachContainerHoldsItsOwn(): void
    {
        $container = new Container;
        $other     = new Container;

        self::assertNull(PendingRegistration::find($container));

        $pending = PendingRegistration::of($container);

        self::assertSame($pending, PendingRegistration::of($container));
        self::assertSame($pending, PendingRegistration::find($container));
        self::assertNotSame($pending, PendingRegistration::of($other));
        self::assertFalse($pending->isPending());
    }

    /**
     * The steps run in the order recorded, each once, a step one of them
     * records included.
     *
     * @return void
     */
    public function testTheStepsRunInOrderOnce(): void
    {
        $pending    = new PendingRegistration;
        $ran        = new \stdClass;
        $ran->steps = [];

        $pending->later(static function () use ($ran): void {
            $ran->steps[] = 'first';
        });
        $pending->later(static function () use ($pending, $ran): void {
            $ran->steps[] = 'second';

            $pending->later(static function () use ($ran): void {
                $ran->steps[] = 'recorded by the second';
            });
        });

        self::assertTrue($pending->isPending());

        $pending->run();
        $pending->run();

        self::assertSame(['first', 'second', 'recorded by the second'], $ran->steps);
        self::assertFalse($pending->isPending());
    }

    /**
     * The steps dropped never run.
     *
     * @return void
     */
    public function testTheStepsDroppedNeverRun(): void
    {
        $pending = new PendingRegistration;
        $ran     = new \ArrayObject;

        $pending->later(static function () use ($ran): void {
            $ran->append('dropped');
        });

        $pending->discard();
        $pending->run();

        self::assertFalse($pending->isPending());
        self::assertCount(0, $ran);
    }
}
