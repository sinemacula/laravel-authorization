<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;

/**
 * Unit tests for the sources of one check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckSources::class)]
final class CheckSourcesTest extends TestCase
{
    /**
     * The sources hold what they are given.
     *
     * @return void
     */
    public function testTheSourcesHoldWhatTheyAreGiven(): void
    {
        $policy     = new Policy('p', []);
        $context    = new CheckContext;
        $permission = static fn (): string => 'posts:view';
        $session    = new SessionCaps;
        $sources    = new CheckSources([$policy], null, [$policy], $context, $permission, $session);

        self::assertSame([$policy], $sources->policies);
        self::assertNull($sources->guardrails);
        self::assertSame([$policy], $sources->boundaries);
        self::assertSame($context, $sources->context);
        self::assertSame('posts:view', ($sources->permission)());
        self::assertSame($session, $sources->session);
    }
}
