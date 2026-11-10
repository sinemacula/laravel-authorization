<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\InheritedPolicies;

/**
 * Unit tests for the policies an identity gets through its roles.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InheritedPolicies::class)]
final class InheritedPoliciesTest extends TestCase
{
    /**
     * By default no policy is inherited, nothing expires, and the hierarchy
     * held.
     *
     * @return void
     */
    public function testNoneByDefault(): void
    {
        $inherited = new InheritedPolicies;

        self::assertSame([], $inherited->keys);
        self::assertNull($inherited->expiresIn);
        self::assertTrue($inherited->stable);
    }

    /**
     * The keys, expiry and stability are kept as given.
     *
     * @return void
     */
    public function testTheValuesAreKept(): void
    {
        $inherited = new InheritedPolicies(['policy-1', 'policy-2'], 60, false);

        self::assertSame(['policy-1', 'policy-2'], $inherited->keys);
        self::assertSame(60, $inherited->expiresIn);
        self::assertFalse($inherited->stable);
    }

    /**
     * The chains and the policies of each role, read for grant usage tracking,
     * are none by default and kept as given.
     *
     * @return void
     */
    public function testTheRoutesOfARoleResolutionAreKept(): void
    {
        $inherited = new InheritedPolicies(['policy-1'], null, true, ['role-1' => ['role-1', 'role-2']], ['role-2' => ['policy-1']]);

        self::assertNull((new InheritedPolicies)->chains);
        self::assertSame([], (new InheritedPolicies)->byRole);
        self::assertSame(['role-1' => ['role-1', 'role-2']], $inherited->chains);
        self::assertSame(['role-2' => ['policy-1']], $inherited->byRole);
    }
}
