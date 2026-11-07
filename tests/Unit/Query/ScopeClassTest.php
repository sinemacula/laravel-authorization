<?php

declare(strict_types = 1);

namespace Tests\Unit\Query;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\ScopeClass;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for one class of a model's rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScopeClass::class)]
final class ScopeClassTest extends TestCase
{
    /**
     * A class is decided in the request's scope by default, and holds what it
     * is given.
     *
     * @return void
     */
    public function testAClassHoldsWhereItsRowsAreDecided(): void
    {
        $tenant = new Reference('teams', '5');
        $class  = new ScopeClass('a', $tenant, true, true);
        $plain  = new ScopeClass('b');

        self::assertSame(['a', $tenant, true, true], [$class->membership, $class->tenant, $class->isBelow, $class->isAdmitted]);
        self::assertSame(['b', null, false, false], [$plain->membership, $plain->tenant, $plain->isBelow, $plain->isAdmitted]);
    }
}
