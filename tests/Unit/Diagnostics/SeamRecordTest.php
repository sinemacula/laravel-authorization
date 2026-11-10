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
     * binding or an earlier alias, and not otherwise.
     *
     * @return void
     */
    public function testARecordSaysWhetherTheContractWasBoundBefore(): void
    {
        $binding = static fn (): mixed => null;

        self::assertFalse((new SeamRecord('A', $binding, 'authorization.default:A', 'Default', null, false, null, null, null))->wasBound());
        self::assertTrue((new SeamRecord('A', $binding, 'authorization.default:A', 'Default', null, false, new \stdClass, null, null))->wasBound());
        self::assertTrue((new SeamRecord('A', $binding, 'authorization.default:A', 'Default', null, false, null, 'Other', null))->wasBound());
    }
}
