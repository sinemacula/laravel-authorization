<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\DependencyPhase;

/**
 * Unit tests for `DependencyPhase`, the parts of a delegated operation's
 * dependencies in the one order every operation locks them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DependencyPhase::class)]
final class DependencyPhaseTest extends TestCase
{
    /**
     * The parts are the actor's, the target's, the holders' and the coverage
     * check's, in that order, backed by their place in it.
     *
     * @return void
     */
    public function testThePartsAreInLockOrder(): void
    {
        self::assertSame([DependencyPhase::ACTOR, DependencyPhase::TARGET, DependencyPhase::HOLDERS, DependencyPhase::COVERAGE], DependencyPhase::cases());
        self::assertSame([0, 1, 2, 3], \array_map(static fn (DependencyPhase $phase): int => $phase->value, DependencyPhase::cases()));
    }
}
