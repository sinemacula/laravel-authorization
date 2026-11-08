<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\IdentityPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the principals an identity owns, as a directory lists them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityPrincipals::class)]
final class IdentityPrincipalsTest extends TestCase
{
    /**
     * A complete list says no principal is missing from it, an incomplete one
     * that some may be; each keeps the principals it names, none by default.
     *
     * @return void
     */
    public function testAListSaysWhetherItIsComplete(): void
    {
        $principals = [new Reference('principal', '1'), new Reference('principal', '2')];

        $complete   = IdentityPrincipals::complete($principals);
        $incomplete = IdentityPrincipals::incomplete($principals);

        self::assertSame($principals, $complete->principals);
        self::assertTrue($complete->isComplete);
        self::assertSame($principals, $incomplete->principals);
        self::assertFalse($incomplete->isComplete);
        self::assertSame([], IdentityPrincipals::complete()->principals);
        self::assertTrue(IdentityPrincipals::complete()->isComplete);
        self::assertSame([], IdentityPrincipals::incomplete()->principals);
        self::assertFalse(IdentityPrincipals::incomplete()->isComplete);
    }
}
