<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\DecisionRoutes;
use SineMacula\Laravel\Authorization\Usage\GrantRoute;
use SineMacula\Laravel\Authorization\Usage\WeighedGrants;
use Tests\Concerns\ReviewsAccess;
use Tests\Concerns\TracksGrantUsage;
use Tests\Feature\Stubs\CustomGrantsIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\TestCase;

/**
 * Feature tests for the grant routes a decision rested on, read from what the
 * resolution cache keeps beside the grants the check weighed, by the rules
 * forward resolution applied: every route behind the permission that matched,
 * of the grantee it matched for alone, and every route of a policy one of the
 * deciding statements belongs to, attached to the subject or to its identity as
 * far as the check weighed each; nothing for a denial by no statement, a
 * resource policy, a `withPolicies()` override, a grantee the package does not
 * resolve, or with no cache.
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
     * An allow by the subject's own permission rests on every route behind that
     * permission, redundant ones included, and on none behind another covering
     * permission or the identity's, which the check never asked for.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAllowRestsOnTheMatchingPermissionsRoutes(): void
    {
        $identity = self::identity('person');
        $ann      = StubSecondIdentity::query()->create(['id' => 'ann']);
        $reader   = self::role('reader');
        $read     = self::permission('posts:read');

        $reader->givePermissionTo($read);

        self::grants()->grantPermission($ann, $read);
        self::grants()->grantRole($ann, $reader);
        self::grants()->grantPermission($ann, self::permission('posts:*'));
        self::grants()->grantPermission($identity, $read);

        $decision = $this->actAs($ann, $identity)->check('posts:read');
        $expected = self::keysHeld($ann, null, self::targeting('posts:read', 'reader'));

        self::assertCount(3, $expected);
        self::assertSame($expected, $this->keysObserved());
        self::assertSame($expected, self::keysOf(DecisionRoutes::of(new Subject($ann, $identity), $decision, self::weighed('posts:read', $ann))));
        self::assertSame([], DecisionRoutes::of(new Subject($ann, $identity), $decision, self::weighed('posts:*', $ann)));
        self::assertSame([], DecisionRoutes::of(new Subject($ann, $identity), Decision::allow(DecisionStage::ALLOW), self::weighed('posts:read', $ann)));
        self::assertSame([], DecisionRoutes::of(new Subject($ann, $identity), $this->actAs($ann, $identity)->check('comments:read'), self::weighed('posts:read', $ann)));
    }

    /**
     * An allow by the identity's permission, asked for only because the
     * subject's own did not match, rests on the identity's routes alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAllowByTheIdentityRestsOnItsRoutes(): void
    {
        $identity = self::identity('person');
        $ann      = StubSecondIdentity::query()->create(['id' => 'ann']);

        self::grants()->grantPermission($ann, self::permission('posts:write'));
        self::grants()->grantPermission($identity, self::permission('posts:read'));

        $this->actAs($ann, $identity)->check('posts:read');

        self::assertSame(self::keysHeld($identity, null, self::targeting('posts:read')), $this->keysObserved());
    }

    /**
     * A decision its statements made rests on the routes of each policy they
     * belong to, each once, unless the policies were not weighed; a resource
     * policy's statement and a statement of a guardrail or boundary stage rest
     * on none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADecidingStatementRestsOnItsPolicysRoutes(): void
    {
        $ann    = self::identity('ann');
        $policy = self::policy('no-delete');

        self::grants()->attachPolicy($ann, $policy);

        $subject  = new Subject($ann, $ann);
        $decision = $this->actAs($ann)->check('posts:delete');
        $key      = Reference::of($policy)->id;
        $used     = DecisionRoutes::of($subject, $decision, new WeighedGrants(true, true));

        self::assertCount(1, $used);
        self::assertSame(self::keysHeld($ann, null, self::targeting('no-delete')), self::keysOf($used));
        self::assertSame([], DecisionRoutes::of($subject, $decision, new WeighedGrants(false, true)));

        $reason     = $decision->reason;
        $statements = [new StatementReference('no-delete', 0, $key), new StatementReference('no-delete', 1, $key), new StatementReference('coded', 0)];

        self::assertNotNull($reason);

        $onResource  = Decision::deny($reason, DecisionStage::DENY, [new StatementReference('no-delete', 0, $key, null, 'post:1')]);
        $atGuardrail = Decision::deny($reason, DecisionStage::GUARDRAIL, [new StatementReference('no-delete', 0, $key)]);
        $twice       = Decision::deny($reason, DecisionStage::DENY, $statements);

        self::assertSame([], DecisionRoutes::of($subject, $onResource, new WeighedGrants(true, true)));
        self::assertSame([], DecisionRoutes::of($subject, $atGuardrail, new WeighedGrants(true, true)));
        self::assertEquals($used, DecisionRoutes::of($subject, $twice, new WeighedGrants(true, true)));
    }

    /**
     * A policy attached to a separate identity rests a decision its statements
     * made on the identity's attachment alone, whether the identity grants to
     * the subject or, for a deny, is of the other kind, and on none when the
     * identity's policies were not weighed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentitysAttachmentIsUsedWhenItDecides(): void
    {
        $ann     = StubSecondIdentity::query()->create(['id' => 'ann']);
        $person  = self::identity('person');
        $machine = StubMachine::query()->create(['id' => 'svc-1']);
        $policy  = self::policy('no-delete');

        self::grants()->grantPermission($ann, self::permission('posts:*'));
        self::grants()->attachPolicy($person, $policy);
        self::grants()->attachPolicy($machine, $policy);

        $byPerson = $this->actAs($ann, $person)->check('posts:delete');
        $used     = DecisionRoutes::of(new Subject($ann, $person), $byPerson, new WeighedGrants(true, true));

        self::assertSame(DecisionStage::DENY, $byPerson->stage);
        self::assertCount(1, $used);
        self::assertSame(self::keysHeld($person, null, self::targeting('no-delete')), self::keysOf($used));
        self::assertSame(self::keysOf($used), $this->keysObserved());
        self::assertSame([], DecisionRoutes::of(new Subject($ann, $person), $byPerson, new WeighedGrants(true, false)));

        $byMachine = $this->actAs($ann, $machine)->check('posts:delete');

        self::assertSame(DecisionStage::DENY, $byMachine->stage);
        self::assertSame(self::keysHeld($machine, null, self::targeting('no-delete')), $this->keysObserved());
    }

    /**
     * An identity of the other kind gives the check its deny statements alone,
     * so its attachment of a policy that allows rests no allow on it, while the
     * subject's own attachment of the same policy does; a deny both attach
     * rests on both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityOfTheOtherKindIsUsedOnlyByItsDenies(): void
    {
        $ann     = self::identity('ann');
        $machine = StubMachine::query()->create(['id' => 'svc-1']);
        $publish = self::policy('publish', true);

        self::grants()->attachPolicy($ann, $publish);
        self::grants()->attachPolicy($machine, $publish);

        $allowed = $this->actAs($ann, $machine)->check('posts:delete');

        self::assertTrue($allowed->isAllowed());
        self::assertSame(self::keysHeld($ann, null, self::targeting('publish')), $this->keysObserved());

        $deny = self::policy('no-delete');

        self::grants()->attachPolicy($ann, $deny);
        self::grants()->attachPolicy($machine, $deny);

        $denied = $this->actAs($ann, $machine)->check('posts:delete');
        $both   = [...self::keysHeld($ann, null, self::targeting('no-delete')), ...self::keysHeld($machine, null, self::targeting('no-delete'))];

        \sort($both);

        self::assertSame(DecisionStage::DENY, $denied->stage);
        self::assertSame($both, $this->keysObserved());
    }

    /**
     * The subject's own attachments rest no decision when a policy resolver of
     * the application's, which may never read them, is bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSubjectsAttachmentsAreNotUsedThroughAnotherResolver(): void
    {
        $ann = self::identity('ann');

        self::grants()->attachPolicy($ann, self::policy('no-delete'));

        $this->app?->instance(PolicyResolver::class, new class implements PolicyResolver {
            /**
             * Return the policies attached to the principal.
             *
             * @param  object  $principal
             * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
             */
            #[\Override]
            public function policiesFor(object $principal): array
            {
                return $principal instanceof AuthorizableIdentity ? $principal->getPolicies() : [];
            }
        });

        self::assertSame(DecisionStage::DENY, $this->actAs($ann)->check('posts:delete')->stage);
        self::assertSame([], $this->keysObserved());
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
        self::assertSame([], DecisionRoutes::of(new Subject($custom, $custom), $decision, self::weighed('reports:read', $custom)));

        $ann = self::identity('ann');

        self::grants()->grantPermission($ann, self::permission('posts:read'));

        $allowed = $this->actAs($ann)->check('posts:read');

        unset($this->app[ResolutionCache::class]);

        self::assertSame([], DecisionRoutes::of(new Subject($ann, $ann), $allowed, self::weighed('posts:read', $ann)));
    }

    /**
     * Return what a check weighed whose permission of the name matched for the
     * grantee, its policies read through the package's resolver.
     *
     * @param  string  $permission
     * @param  object  $grantee
     * @return \SineMacula\Laravel\Authorization\Usage\WeighedGrants
     */
    private static function weighed(string $permission, object $grantee): WeighedGrants
    {
        $weighed = new WeighedGrants(true, true);

        $weighed->notePermission($permission, $grantee);

        return $weighed;
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
