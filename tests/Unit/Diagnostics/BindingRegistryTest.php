<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\BindingRegistry;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRecord;

/**
 * Unit tests for the record of every seam the package bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BindingRegistry::class)]
final class BindingRegistryTest extends TestCase
{
    /**
     * Each container holds its own registry, the same each time it is asked
     * for.
     *
     * @return void
     */
    public function testEachContainerHoldsItsOwn(): void
    {
        $container = new Container;

        self::assertSame(BindingRegistry::of($container), BindingRegistry::of($container));
        self::assertNotSame(BindingRegistry::of($container), BindingRegistry::of(new Container));
    }

    /**
     * A record is kept by its contract, a later record of the contract in place
     * of the earlier, in the order first recorded.
     *
     * @return void
     */
    public function testRecordsAreKeptByContract(): void
    {
        $registry = new BindingRegistry;
        $first    = self::record('First', null);
        $second   = self::record('Second', new \stdClass);
        $again    = self::record('First', null);

        $registry->record($first);
        $registry->record($second);
        $registry->record($again);

        self::assertSame(['First' => $again, 'Second' => $second], $registry->all());
        self::assertSame($second, $registry->get('Second'));
        self::assertNull($registry->get('Third'));
    }

    /**
     * Return a record of the contract, holding the earlier binding given.
     *
     * @param  string  $contract
     * @param  object|null  $earlier
     * @return \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord
     */
    private static function record(string $contract, ?object $earlier): SeamRecord
    {
        return new SeamRecord($contract, static fn (): mixed => null, "authorization.default:{$contract}", null, null, false, null, $earlier, null, null);
    }
}
