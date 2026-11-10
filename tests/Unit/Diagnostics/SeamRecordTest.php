<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRecord;

/**
 * Unit tests for what the package recorded of one seam as it bound it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamRecord::class)]
final class SeamRecordTest extends TestCase
{
    /**
     * A record says the contract was bound before when it holds an earlier
     * closure, an earlier instance or an earlier alias, and not otherwise.
     *
     * @return void
     */
    public function testARecordSaysWhetherTheContractWasBoundBefore(): void
    {
        self::assertFalse(self::record()->wasBound());
        self::assertTrue(self::record(earlier: static fn (): mixed => null)->wasBound());
        self::assertTrue(self::record(earlierInstance: new \stdClass)->wasBound());
        self::assertTrue(self::record(earlierAlias: 'Other')->wasBound());
    }

    /**
     * What supplies the contract is earlier when it is the closure or the
     * instance held before the package registered, and nothing is earlier when
     * nothing supplies it.
     *
     * @return void
     */
    public function testEitherEarlierSupplierMatches(): void
    {
        $closure  = static fn (): mixed => null;
        $instance = new \stdClass;
        $record   = self::record(earlier: $closure, earlierInstance: $instance);

        self::assertTrue($record->isEarlier($closure));
        self::assertTrue($record->isEarlier($instance));
        self::assertFalse($record->isEarlier(new \stdClass));
        self::assertFalse($record->isEarlier(static fn (): mixed => null));
        self::assertFalse(self::record()->isEarlier(null));
    }

    /**
     * The decorator that replaced the instance held is shown as that instance,
     * and is earlier only when that instance was held as the package
     * registered; any other instance, and none, as it is.
     *
     * @return void
     */
    public function testTheDecoratorIsUnwrapped(): void
    {
        $held    = new \stdClass;
        $wrapper = new \ArrayObject;
        $other   = new \stdClass;
        $record  = self::record(earlierInstance: $held);
        $wrapped = $record->wrappedBy($wrapper, $held);
        $later   = $record->wrappedBy($wrapper, $other);
        $added   = ['wrapper' => true, 'wrapped' => true];

        self::assertNull($record->wrapper);
        self::assertNull($record->wrapped);
        self::assertSame([$wrapper, $held], [$wrapped->wrapper, $wrapped->wrapped]);
        self::assertSame(\array_diff_key(\get_object_vars($record), $added), \array_diff_key(\get_object_vars($wrapped), $added));
        self::assertSame($held, $wrapped->unwrap($wrapper));
        self::assertTrue($wrapped->isEarlier($wrapper));
        self::assertTrue($wrapped->isEarlier($held));
        self::assertSame($other, $later->unwrap($wrapper));
        self::assertFalse($later->isEarlier($wrapper));
        self::assertTrue($later->isEarlier($held));
        self::assertFalse($record->isEarlier($wrapper));
        self::assertSame($other, $wrapped->unwrap($other));
        self::assertNull($wrapped->unwrap(null));
        self::assertNull($record->unwrap(null));
        self::assertSame($wrapper, $record->unwrap($wrapper));
    }

    /**
     * Return a record of contract `A`, with what was bound before given.
     *
     * @param  (\Closure(mixed ...): mixed)|null  $earlier
     * @param  object|null  $earlierInstance
     * @param  string|null  $earlierAlias
     * @return \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord
     */
    private static function record(?\Closure $earlier = null, ?object $earlierInstance = null, ?string $earlierAlias = null): SeamRecord
    {
        $binding = static fn (): mixed => null;

        return new SeamRecord('A', $binding, 'authorization.default:A', 'Default', 'authorization.a', true, $earlier, $earlierInstance, $earlierAlias, 'Acme\Provider');
    }
}
