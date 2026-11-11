<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\GuardrailException;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the refusals of the rules guardrails keep, each naming its
 * reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardrailException::class)]
final class GuardrailExceptionTest extends TestCase
{
    /**
     * The exception is a logic exception, and each reason is a code of its own.
     *
     * @return void
     */
    public function testIsALogicExceptionWithAReasonCodeForEachRefusal(): void
    {
        self::assertInstanceOf(\LogicException::class, GuardrailException::inline('cap'));
        self::assertSame('not_permitted', GuardrailException::NOT_PERMITTED);
        self::assertSame('inline', GuardrailException::INLINE);
        self::assertSame('in_use', GuardrailException::IN_USE);
    }

    /**
     * An actor refused a tenant's guardrails is told it needs the right through
     * a grant from above the tenant, and named with the tenant.
     *
     * @return void
     */
    public function testNotPermittedOnATenantNamesTheActorTheTenantAndTheGrantNeeded(): void
    {
        $actor     = new Reference('user', 'user-1');
        $tenant    = new Reference('stub_tenant', 'tenant-a');
        $exception = GuardrailException::notPermitted($actor, $tenant);

        self::assertSame(
            '\'user:user-1\' may not change the guardrails of tenant \'stub_tenant:tenant-a\': it must hold \'authorization:guardrail.manage\' through a grant held at'
            . ' an ancestor of the tenant that reaches it, or a platform-wide one, never one held within the tenant.',
            $exception->getMessage(),
        );
        self::assertSame(GuardrailException::NOT_PERMITTED, $exception->getReason());
        self::assertSame($actor, $exception->getActor());
        self::assertSame([$tenant], $exception->getTenants());
        self::assertNull($exception->getPolicyName());
    }

    /**
     * An actor refused the platform's guardrails is told it needs a
     * platform-wide grant.
     *
     * @return void
     */
    public function testNotPermittedOnThePlatformNamesThePlatformWideGrant(): void
    {
        $exception = GuardrailException::notPermitted(new Reference('user', 'user-1'), null);

        self::assertSame(
            '\'user:user-1\' may not change the guardrails of the platform: it must hold \'authorization:guardrail.manage\' through a platform-wide grant.',
            $exception->getMessage(),
        );
        self::assertSame([null], $exception->getTenants());
    }

    /**
     * An inline policy is refused by name, about no actor or scope.
     *
     * @return void
     */
    public function testInlineNamesThePolicy(): void
    {
        $exception = GuardrailException::inline('mine');

        self::assertSame('Inline policy \'mine\' belongs to one grantee and cannot be set as a guardrail; set a managed policy.', $exception->getMessage());
        self::assertSame(GuardrailException::INLINE, $exception->getReason());
        self::assertSame('mine', $exception->getPolicyName());
        self::assertSame([], $exception->getTenants());
        self::assertNull($exception->getActor());
    }

    /**
     * A policy in use as a guardrail names every scope it caps, the platform
     * included, and the change refused.
     *
     * @return void
     */
    public function testInUseNamesEveryScopeAndTheChange(): void
    {
        $tenant    = new Reference('stub_tenant', 'tenant-a');
        $exception = GuardrailException::inUse('rail', [null, $tenant], 'deleting');

        self::assertSame(
            'Policy \'rail\' is a guardrail on the platform, stub_tenant:tenant-a; remove each guardrail through the guardrail service before deleting the policy.',
            $exception->getMessage(),
        );
        self::assertSame(GuardrailException::IN_USE, $exception->getReason());
        self::assertSame('rail', $exception->getPolicyName());
        self::assertSame([null, $tenant], $exception->getTenants());
        self::assertNull($exception->getActor());
    }

    /**
     * Guardrail rows naming half a tenant are counted as malformed, never named
     * as the platform or a tenant, and said to be removed with the policy's
     * guardrail on the platform; they are among no scope of the refusal.
     *
     * @return void
     */
    public function testInUseCountsTheMalformedRows(): void
    {
        $tenant    = new Reference('stub_tenant', 'tenant-a');
        $exception = GuardrailException::inUse('rail', [$tenant], 'editing', 2);

        self::assertSame(
            'Policy \'rail\' is a guardrail on stub_tenant:tenant-a, 2 malformed row(s) naming half a tenant; remove each guardrail through the guardrail '
            . 'service (a malformed row is removed with the policy\'s guardrail on the platform) before editing the policy.',
            $exception->getMessage(),
        );
        self::assertSame([$tenant], $exception->getTenants());
        $alone = GuardrailException::inUse('rail', [], 'deleting', 1);

        self::assertStringStartsWith('Policy \'rail\' is a guardrail on 1 malformed row(s) naming half a tenant; ', $alone->getMessage());
    }
}
