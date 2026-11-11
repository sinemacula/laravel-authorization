<?php

declare(strict_types = 1);

namespace Tests\Feature\ForgettingDecisions;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\DecisionMemory;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\ChangingSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for an authorization scope already in place when the decisions
 * of the request are forgotten while it runs (N112): it is held in place until
 * its callback returns, and the request's tenant is read afresh afterwards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationScope::class)]
final class AuthorizationScopeTest extends TestCase
{
    /**
     * The request's own scope, already in place, stays in place while the
     * request moves to another tenant and the decisions are forgotten, and the
     * request's new tenant is read once the callback returns.
     *
     * @return void
     */
    public function testAScopeAlreadyInPlaceIsHeldWhileTheDecisionsAreForgotten(): void
    {
        $first    = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);
        $second   = StubTenant::query()->create(['id' => 'tenant-b', 'name' => 'B']);
        $user     = StubIdentity::create(['id' => 'user-1']);
        $resolver = new ChangingSubjectResolver(new Subject($user, $user, $first));

        $this->container()->instance(SubjectResolver::class, $resolver);
        $this->container()->forgetInstance(ResolvedTenant::class);

        $inside = AuthorizationScope::current()->within(static function () use ($resolver, $user, $second): ?string {
            $resolver->subject = new Subject($user, $user, $second);

            DecisionMemory::current()->forget(new LastDecisionStore);

            return self::tenantId();
        });

        self::assertSame('tenant-a', $inside);
        self::assertSame('tenant-b', self::tenantId());
    }

    /**
     * Return the id of the tenant checks are decided in now, or null for the
     * platform.
     *
     * @return string|null
     */
    private static function tenantId(): ?string
    {
        $tenant = TenantScope::currentTenant();

        return $tenant === null ? null : $tenant[1];
    }
}
