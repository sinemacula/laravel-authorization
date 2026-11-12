<?php

declare(strict_types = 1);

namespace Tests\Unit\Exclusions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `ExclusionConflict`: a holder of both roles of a pair, with a
 * route to each.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExclusionConflict::class)]
final class ExclusionConflictTest extends TestCase
{
    /**
     * The conflict holds its holder, the identity it came through and its two
     * routes, and is ordered by its holder, its identity, then its routes.
     *
     * @return void
     */
    public function testHoldsTheHolderAndBothRoutes(): void
    {
        $holder   = new Reference('member', '7');
        $identity = new Reference('user', '1');
        $first    = new ExclusionRoute($identity, new Reference('role', 'a'), [new Reference('role', 'a')], GrantScope::platform(), GrantScope::platform());
        $second   = new ExclusionRoute($holder, new Reference('role', 'b'), [new Reference('role', 'b')], GrantScope::platform(), GrantScope::platform());
        $conflict = new ExclusionConflict($holder, $identity, $first, $second);

        self::assertSame([$holder, $identity, $first, $second], [$conflict->holder, $conflict->identity, $conflict->first, $conflict->second]);
        self::assertSame(['member', '7', 'user', '1', ...$first->orderKey(), ...$second->orderKey()], $conflict->orderKey());
        self::assertSame(['member', '7', null, null, ...$first->orderKey(), ...$second->orderKey()], (new ExclusionConflict($holder, null, $first, $second))->orderKey());
    }
}
