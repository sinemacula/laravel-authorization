<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\GrantRoute;
use SineMacula\Laravel\Authorization\Usage\StoredGrant;

/**
 * Unit tests for what a resolution found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Resolution::class)]
final class ResolutionTest extends TestCase
{
    /**
     * A resolution with nothing else said never expires and may be stored.
     *
     * @return void
     */
    public function testDefaultsToStableWithoutExpiry(): void
    {
        $resolution = new Resolution(['posts:read']);

        self::assertSame(['posts:read'], $resolution->value);
        self::assertNull($resolution->expiresIn);
        self::assertTrue($resolution->stable);
    }

    /**
     * A resolution keeps no routes unless given them, and keeps those given.
     *
     * @return void
     */
    public function testRoutesAreKeptOnlyWhenGiven(): void
    {
        $route = new GrantRoute('k', new StoredGrant(GrantTarget::PERMISSION, 'p', new Reference('user', 'u'), null, null, null, null));

        self::assertNull((new Resolution(['posts:read']))->routes);
        self::assertSame(['posts:read' => [$route]], (new Resolution(['posts:read'], null, true, ['posts:read' => [$route]]))->routes);
    }
}
