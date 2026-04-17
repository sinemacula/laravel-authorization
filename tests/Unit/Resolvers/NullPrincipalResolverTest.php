<?php

declare(strict_types = 1);

namespace Tests\Unit\Resolvers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver;

/**
 * Unit tests for the anonymous-safe default resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(NullPrincipalResolver::class)]
final class NullPrincipalResolverTest extends TestCase
{
    /**
     * Default resolver always returns null.
     *
     * @return void
     */
    public function testResolveReturnsNull(): void
    {
        self::assertNull((new NullPrincipalResolver)->resolve());
    }
}
