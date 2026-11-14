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

    /**
     * The keys of the policies reached only through attachments whose denies
     * alone count are none by default and kept as given.
     *
     * @return void
     */
    public function testThePoliciesWhoseDeniesAloneCountAreKept(): void
    {
        self::assertSame([], (new InheritedPolicies)->denyOnly);
        self::assertSame(['policy-1'], (new InheritedPolicies(['policy-1', 'policy-2'], denyOnly: ['policy-1']))->denyOnly);
    }

    /**
     * The activations behind each policy are none by default and kept as given.
     *
     * @return void
     */
    public function testTheActivationsBehindEachPolicyAreKept(): void
    {
        self::assertSame([], (new InheritedPolicies)->activations);
        self::assertSame(['policy-1' => ['activation-1']], (new InheritedPolicies(['policy-1'], activations: ['policy-1' => ['activation-1']]))->activations);
    }
}
