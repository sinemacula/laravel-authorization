<?php

declare(strict_types = 1);

namespace Tests\Unit\Contracts;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Context\ClockEnvironmentContext;
use SineMacula\Laravel\Authorization\Context\GuardAuthenticationContext;
use SineMacula\Laravel\Authorization\Context\RoutedRequestContext;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;

/**
 * Unit tests for the marker of a seam that reads the request alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ScopeInvariantTest extends TestCase
{
    /**
     * The marker declares nothing, and the package's default seams carry it.
     *
     * @return void
     */
    public function testItMarksThePackagesDefaultSeams(): void
    {
        self::assertSame([], (new \ReflectionClass(ScopeInvariant::class))->getMethods());

        foreach ([GuardAuthenticationContext::class, RoutedRequestContext::class, ClockEnvironmentContext::class, RefusingRequirementChecker::class] as $seam) {
            self::assertContains(ScopeInvariant::class, \class_implements($seam), $seam);
        }
    }
}
