<?php

declare(strict_types = 1);

namespace Tests\Unit\Usage;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Usage\WeighedGrants;

/**
 * Unit tests for what one tracked check weighed: the grantee whose permission
 * matched, given only for the permission noted, and whether the subject's and
 * its identity's policies were read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WeighedGrants::class)]
final class WeighedGrantsTest extends TestCase
{
    /**
     * No grantee is given until a permission is noted, and then only for that
     * permission; a later note replaces it.
     *
     * @return void
     */
    public function testTheGranteeIsGivenOnlyForThePermissionNoted(): void
    {
        $subject  = new \stdClass;
        $identity = new \stdClass;
        $weighed  = new WeighedGrants(true, false);

        self::assertNull($weighed->granteeOf('posts:read'));

        $weighed->notePermission('posts:read', $subject);

        self::assertSame($subject, $weighed->granteeOf('posts:read'));
        self::assertNull($weighed->granteeOf('posts:*'));

        $weighed->notePermission('posts:*', $identity);

        self::assertSame($identity, $weighed->granteeOf('posts:*'));
        self::assertNull($weighed->granteeOf('posts:read'));
        self::assertSame([true, false], [$weighed->areSubjectPoliciesWeighed, $weighed->areIdentityPoliciesWeighed]);
    }
}
