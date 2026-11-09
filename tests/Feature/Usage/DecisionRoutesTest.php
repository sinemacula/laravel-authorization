<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\DecisionRoutes;
use SineMacula\Laravel\Authorization\Usage\GrantRoute;
use Tests\Concerns\ReviewsAccess;
use Tests\Concerns\TracksGrantUsage;
use Tests\Feature\Stubs\CustomGrantsIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\TestCase;

/**
 * Feature tests for the grant routes a decision used, read from what the
 * resolution cache keeps beside the subject's grants: every route behind a
 * covering permission, the identity's resolved for it, and every route of a
 * policy one of its statements belongs to; nothing for a denial by no
 * statement, a resource policy, a `withPolicies()` override, a grantee the
 * package does not resolve, or with no cache.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionRoutes::class)]
final class DecisionRoutesTest extends TestCase
{
    use ReviewsAccess, TracksGrantUsage;

    /**
     * An allow by a permission uses the routes behind every held permission
     * that covers the action, the identity's included though the check never
     * needed them, and none behind a permission that does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAllowUsesEveryCoveringPermissionsRoutes(): void
    {
        $identity = self::identity('person');
        $ann      = StubSecondIdentity::query()->create(['id' => 'ann']);

        self::grants()->grantPermission($ann, self::permission('posts:read'));
        self::grants()->grantPermission($ann, self::permission('posts:write'));
        self::grants()->grantPermission($identity, self::permission('posts:*'));

        $subject  = new Subject($ann, $identity);
        $decision = $this->actAs($ann, $identity)->check('posts:read');

        self::assertSame(self::keysHeld($ann, $identity, self::targeting('posts:read', 'posts:*')), self::keysOf(DecisionRoutes::of($subject, 'posts:read', $decision, false)));
        self::assertSame([], DecisionRoutes::of($subject, 'posts:read', Decision::allow(DecisionStage::ALLOW), false));
        self::assertSame([], DecisionRoutes::of($subject, 'posts:read', $this->actAs($ann, $identity)->check('comments:read'), false));
    }

    /**
     * A decision its statements made uses the routes of each policy they belong
     * to, attached to the subject or its identity, unless the policies were
     * overridden; a resource policy's statement and a statement of a guardrail
     * or boundary stage use none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADecidingStatementUsesItsPolicysRoutes(): void
    {
        $ann    = self::identity('ann');
        $policy = self::policy('no-delete');

        self::grants()->attachPolicy($ann, $policy);

        $subject  = new Subject($ann, $ann);
        $decision = $this->actAs($ann)->check('posts:delete');
        $key      = Reference::of($policy)->id;
        $routes   = self::keysOf(DecisionRoutes::of($subject, 'posts:delete', $decision, false));

        self::assertSame(self::keysHeld($ann, null, self::targeting('no-delete')), $routes);
        self::assertSame([], DecisionRoutes::of($subject, 'posts:delete', $decision, true));

        $reason     = $decision->reason;
        $statements = [new StatementReference('no-delete', 0, $key), new StatementReference('no-delete', 1, $key), new StatementReference('coded', 0)];

        self::assertNotNull($reason);

        $onResource  = Decision::deny($reason, DecisionStage::DENY, [new StatementReference('no-delete', 0, $key, null, 'post:1')]);
        $atGuardrail = Decision::deny($reason, DecisionStage::GUARDRAIL, [new StatementReference('no-delete', 0, $key)]);
        $twice       = Decision::deny($reason, DecisionStage::DENY, $statements);

        self::assertSame([], DecisionRoutes::of($subject, 'posts:delete', $onResource, false));
        self::assertSame([], DecisionRoutes::of($subject, 'posts:delete', $atGuardrail, false));
        self::assertSame($routes, self::keysOf(DecisionRoutes::of($subject, 'posts:delete', $twice, false)));
    }

    /**
     * A grantee whose grants the package does not resolve, and a check with no
     * cache bound, use no route.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGranteeThatCannotSayUsesNoRoute(): void
    {
        $custom   = CustomGrantsIdentity::query()->create(['id' => 'custom']);
        $decision = $this->actAs($custom)->check('reports:read');

        self::assertTrue($decision->isAllowed());
        self::assertSame([], DecisionRoutes::of(new Subject($custom, $custom), 'reports:read', $decision, false));

        $ann = self::identity('ann');

        self::grants()->grantPermission($ann, self::permission('posts:read'));

        $allowed = $this->actAs($ann)->check('posts:read');

        unset($this->app[ResolutionCache::class]);

        self::assertSame([], DecisionRoutes::of(new Subject($ann, $ann), 'posts:read', $allowed, false));
    }

    /**
     * Return the key of each route, each once, sorted.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>  $routes
     * @return list<string>
     */
    private static function keysOf(array $routes): array
    {
        $keys = \array_values(\array_unique(\array_map(static fn (GrantRoute $route): string => $route->key, $routes)));

        \sort($keys);

        return $keys;
    }
}
