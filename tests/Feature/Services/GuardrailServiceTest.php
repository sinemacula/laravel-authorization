<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailRemoved;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailSet;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\GuardrailException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException;
use SineMacula\Laravel\Authorization\Exceptions\UnwrittenGrantException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\RacesDelegatedCalls;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\RecordsRowLocks;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `GuardrailService`, which sets and removes the guardrails
 * of tenants and of the platform for an actor that may change them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GuardrailService::class)]
final class GuardrailServiceTest extends TestCase
{
    use ActsAsTenant, ComparesReferences, RacesDelegatedCalls, ReadsDispatchedEvents, RecordsRowLocks;

    /**
     * The service is bound once in the container.
     *
     * @return void
     */
    public function testIsBoundAsASingleton(): void
    {
        self::assertInstanceOf(GuardrailService::class, self::service());
        self::assertSame(self::service(), self::service());
    }

    /**
     * A guardrail is set on the platform, its row recording the actor, and
     * reported once with the operation, its actor, the policy, its name and the
     * platform scope, which reaches below and names no application.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSetsAPlatformGuardrail(): void
    {
        Event::fake([GuardrailSet::class]);

        $actor  = self::manager();
        $policy = self::rail('platform-cap');

        self::assertSame(GrantOutcome::GRANTED, self::service()->set($policy, null, ActingContext::for($actor)));

        $row = (array) DB::table('guardrails')->sole();

        self::assertSame([null, null, $actor->getMorphClass(), 'admin-1'], [$row['tenant_type'], $row['tenant_id'], $row['granted_by_type'], $row['granted_by_id']]);
        self::assertSame($policy->id, $row['policy_id']);

        $events = self::dispatchedEvents(GuardrailSet::class);

        self::assertCount(1, $events);
        self::assertTrue(self::refersTo($events[0]->policy, $policy));
        self::assertTrue(self::refersTo($events[0]->operation->actor, $actor));
        self::assertSame('platform-cap', $events[0]->name);
        self::assertNull($events[0]->scope->tenant);
        self::assertNull($events[0]->scope->application);
        self::assertTrue($events[0]->scope->includeSubtree);
    }

    /**
     * Setting a guardrail the scope already has changes nothing and reports
     * nothing; one policy is set once per scope, and a scope holds any number
     * of guardrails.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSetsAPolicyOncePerScope(): void
    {
        $tenant = self::createTenant('tenant-a');
        $actor  = self::manager();
        $first  = self::rail('first');
        $second = self::rail('second');

        self::service()->set($first, null, ActingContext::for($actor));

        Event::fake([GuardrailSet::class]);

        self::assertSame(GrantOutcome::UNCHANGED, self::service()->set($first, null, ActingContext::for($actor)));
        self::assertSame([], self::dispatchedEvents(GuardrailSet::class));
        self::assertSame(GrantOutcome::GRANTED, self::service()->set($first, $tenant, ActingContext::for($actor)));
        self::assertSame(GrantOutcome::GRANTED, self::service()->set($second, null, ActingContext::for($actor)));
        self::assertSame(GrantOutcome::GRANTED, self::service()->set($second, Reference::of($tenant), ActingContext::for($actor)));
        self::assertSame(4, DB::table('guardrails')->count());

        $events = self::dispatchedEvents(GuardrailSet::class);

        self::assertCount(3, $events);
        self::assertTrue(self::refersTo($events[0]->scope->tenant, $tenant));
        self::assertTrue(self::refersTo($events[2]->scope->tenant, $tenant));
    }

    /**
     * A guardrail is removed from the scope named, reported with the policy it
     * was and the scope; removing it elsewhere, or again, removes nothing and
     * reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesFromTheScope(): void
    {
        $tenant = self::createTenant('tenant-a');
        $actor  = self::manager();
        $policy = self::rail('tenant-cap');

        self::service()->set($policy, $tenant, ActingContext::for($actor));

        Event::fake([GuardrailRemoved::class]);

        self::assertFalse(self::service()->remove($policy, null, ActingContext::for($actor)));
        self::assertTrue(self::service()->remove($policy, $tenant, ActingContext::for($actor)));
        self::assertFalse(self::service()->remove($policy, $tenant, ActingContext::for($actor)));
        self::assertSame(0, DB::table('guardrails')->count());

        $events = self::dispatchedEvents(GuardrailRemoved::class);

        self::assertCount(1, $events);
        self::assertTrue(self::refersTo($events[0]->policy, $policy));
        self::assertTrue(self::refersTo($events[0]->operation->actor, $actor));
        self::assertSame('tenant-cap', $events[0]->name);
        self::assertSame([PackagePermissions::GUARDRAIL_MANAGE], $events[0]->operation->actions);
        self::assertTrue(self::refersTo($events[0]->scope->tenant, $tenant));
        self::assertTrue($events[0]->scope->includeSubtree);
    }

    /**
     * The right is decided inside the change's transaction, setting and
     * removing alike, and the change is reported with the acting principal,
     * delegated, under `authorization:guardrail.manage`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRightIsDecidedInsideTheTransaction(): void
    {
        $actor  = self::manager();
        $policy = self::rail('cap');
        $levels = [];
        $base   = AuthorizationConnection::connection()->transactionLevel();

        Event::listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use (&$levels): void {
            if ($event->action !== PackagePermissions::GUARDRAIL_MANAGE) {
                return;
            }

            $levels[] = AuthorizationConnection::connection()->transactionLevel();
        });

        Event::fake([GuardrailSet::class]);

        self::service()->set($policy, null, ActingContext::for($actor));
        self::service()->remove($policy, null, ActingContext::for($actor));

        self::assertSame([$base + 1, $base + 1], $levels);
        Event::assertDispatched(GuardrailSet::class, static fn (GuardrailSet $event): bool => !$event->operation->isTrusted
            && $event->operation->actor?->id === 'admin-1'
            && $event->operation->actions    === [PackagePermissions::GUARDRAIL_MANAGE]);
    }

    /**
     * An actor that may not change the guardrails of the scope is refused,
     * naming the reason, before anything is read or written, setting and
     * removing alike.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAnActorThatMayNotChangeTheScope(): void
    {
        $tenant = self::createTenant('tenant-a');
        $actor  = StubIdentity::create(['id' => 'user-1']);
        $policy = self::rail('cap');

        self::service()->set($policy, $tenant, ActingContext::for(self::manager()));

        Event::fake([GuardrailSet::class, GuardrailRemoved::class]);

        $actor->givePermission(Permission::create(['name' => 'posts:read']));

        $calls = [
            static fn () => self::service()->set(self::rail('other'), null, ActingContext::for($actor)),
            static fn () => self::service()->remove($policy, $tenant, ActingContext::for($actor)),
        ];

        foreach ($calls as $call) {
            try {
                $call();
                self::fail('The actor was not refused.');
            } catch (GuardrailException $exception) {
                self::assertSame(GuardrailException::NOT_PERMITTED, $exception->getReason());
                self::assertTrue(self::refersTo($exception->getActor(), $actor));
            }
        }

        self::assertSame(1, DB::table('guardrails')->count());
        self::assertSame([], self::dispatchedEvents(GuardrailSet::class));
        self::assertSame([], self::dispatchedEvents(GuardrailRemoved::class));
    }

    /**
     * The guardrails of a tenant are changed from above it: by an actor whose
     * right is held at an ancestor and reaches the tenant, never by one whose
     * right is held within the tenant itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsGuardrailsAreChangedFromAboveIt(): void
    {
        [$org, $account] = \array_map(self::createTenant(...), ['org', 'account']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($account), Reference::of($org)));

        $permission = Permission::create(['name' => PackagePermissions::GUARDRAIL_MANAGE]);
        $above      = StubIdentity::create(['id' => 'org-admin']);
        $within     = StubIdentity::create(['id' => 'account-admin']);
        $policy     = self::rail('cap');

        $above->givePermission($permission, tenant: $org);
        $within->givePermission($permission, tenant: $account);

        self::assertSame(GrantOutcome::GRANTED, self::service()->set($policy, $account, ActingContext::for($above)));

        $this->expectException(GuardrailException::class);

        self::service()->remove($policy, $account, ActingContext::for($within));
    }

    /**
     * A removal lifts a cap across the tenant's whole subtree, so it is weighed
     * across it, while a set only adds one: an actor holding the right at the
     * organisation, but denied it by a role it holds in a team below the
     * account, sets a guardrail on the account but is refused its removal,
     * which writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalIsWeighedAcrossTheSubtreeASetIsNot(): void
    {
        [$org, $account, $team] = \array_map(self::createTenant(...), ['org', 'account', 'team']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($account), Reference::of($org))->put(Reference::of($team), Reference::of($account)));

        $actor  = StubIdentity::create(['id' => 'org-admin']);
        $role   = Role::create(['name' => 'restricted', 'rank' => 8]);
        $policy = self::rail('cap');

        $actor->givePermission(Permission::create(['name' => PackagePermissions::GUARDRAIL_MANAGE]), tenant: $org);
        $role->attachPolicy(self::policy('restricting', [['effect' => 'deny', 'actions' => [PackagePermissions::GUARDRAIL_MANAGE]]]));
        $actor->assignRole($role, tenant: $team);

        self::assertSame(GrantOutcome::GRANTED, self::service()->set($policy, $account, ActingContext::for($actor)));
        self::assertRefusedAs(GuardrailException::class, static fn (): bool => self::service()->remove($policy, $account, ActingContext::for($actor)));
        self::assertSame(1, DB::table('guardrails')->count());
    }

    /**
     * No guardrail locks the guardrails: with a platform guardrail that allows
     * only `posts:*` in place, guardrails are still set on the platform and on
     * a tenant, and the guardrail itself is still removed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardrailThatDoesNotAllowManagingGuardrailsIsStillRemoved(): void
    {
        $tenant = self::createTenant('tenant-a');
        $actor  = self::manager();
        $posts  = self::policy('posts-only', [['effect' => 'allow', 'actions' => ['posts:*']]]);
        $other  = self::rail('other');

        self::assertSame(GrantOutcome::GRANTED, self::service()->set($posts, null, ActingContext::for($actor)));
        self::assertSame(GrantOutcome::GRANTED, self::service()->set($other, null, ActingContext::for($actor)));
        self::assertSame(GrantOutcome::GRANTED, self::service()->set($other, $tenant, ActingContext::for($actor)));
        self::assertTrue(self::service()->remove($posts, null, ActingContext::for($actor)));
        self::assertSame(0, DB::table('guardrails')->where('policy_id', $posts->id)->count());
    }

    /**
     * A platform guardrail whose document cannot be read, which denies every
     * other check as an invalid policy, is still removed through the service.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnreadablePlatformGuardrailIsStillRemoved(): void
    {
        $actor  = self::manager();
        $broken = self::rail('broken');

        self::service()->set($broken, null, ActingContext::for($actor));

        DB::table('policies')->where('id', $broken->id)->update(['document' => '{"statements": "broken"}']);

        self::assertTrue(self::service()->remove($broken, null, ActingContext::for($actor)));
        self::assertSame(0, DB::table('guardrails')->count());
    }

    /**
     * A tenant's guardrail that does not allow managing guardrails keeps no one
     * from changing the guardrails of its own tenant or of the tenants below
     * it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsGuardrailNeverLocksTheGuardrailsAtOrBelowIt(): void
    {
        [$org, $account, $team] = \array_map(self::createTenant(...), ['org', 'account', 'team']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)
            ->put(Reference::of($account), Reference::of($org))
            ->put(Reference::of($team), Reference::of($account)));

        $actor    = self::manager();
        $blocking = self::rail('blocking');
        $other    = self::rail('other');

        self::service()->set($blocking, $account, ActingContext::for($actor));

        self::assertSame(GrantOutcome::GRANTED, self::service()->set($other, $account, ActingContext::for($actor)));
        self::assertSame(GrantOutcome::GRANTED, self::service()->set($other, $team, ActingContext::for($actor)));
        self::assertTrue(self::service()->remove($other, $team, ActingContext::for($actor)));
        self::assertTrue(self::service()->remove($blocking, $account, ActingContext::for($actor)));
    }

    /**
     * Setting a guardrail locks the actor's authority first, as every delegated
     * operation does, then the policy's row, before the right is decided and
     * before anything is written, so an edit of the policy made meanwhile waits
     * until the guardrail is there to refuse it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSettingAGuardrailLocksTheActorThenItsPolicy(): void
    {
        $actor  = self::manager();
        $policy = self::rail('cap');
        $locks  = $this->recordRowLocks();

        self::service()->set($policy, null, ActingContext::for($actor));

        $locked = $locks->getArrayCopy();
        $first  = \array_search(['policies', [$policy->id]], $locked, true);

        self::assertIsInt($first);
        self::assertSame(
            ['authorizable_roles', 'authorizable_permissions', 'authorizable_policies', 'authorizable_boundaries', 'guardrails', 'resource_policies', 'permissions'],
            \array_column(\array_slice($locked, 0, $first), 0),
        );
    }

    /**
     * The actor's right revoked between the decision and the write has the
     * change tried again, under the concurrency protocol, and refused, as the
     * actor no longer holds it; nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARightRevokedMeanwhileIsRefusedOnTheRetry(): void
    {
        $actor     = self::manager();
        $policy    = self::rail('cap');
        $admin     = StubIdentity::query()->whereKey('admin-1')->firstOrFail();
        $revoke    = static fn (): int => GrantService::instance()?->revokePermission($admin, PackagePermissions::GUARDRAIL_MANAGE) ?? 0;
        $decisions = self::raceWith(PackagePermissions::GUARDRAIL_MANAGE, $revoke);

        try {
            self::service()->set($policy, null, ActingContext::for($actor));

            self::fail('The change was made.');
        } catch (GuardrailException $exception) {
            self::assertSame(GuardrailException::NOT_PERMITTED, $exception->getReason());
        }

        self::assertSame([true, false], $decisions->getArrayCopy());
        self::assertSame(0, DB::table('guardrails')->count());
    }

    /**
     * A policy rewritten between the decision and the write has the change
     * tried again and made on the policy as rewritten, once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyRewrittenMeanwhileIsSetAsRewritten(): void
    {
        $actor   = self::manager();
        $policy  = self::rail('cap');
        $edit    = ['statements' => [['effect' => 'allow', 'actions' => ['posts:edit']]]];
        $rewrite = static fn (): Policy => PolicyService::instance()?->rewrite(self::stored($policy), $edit) ?? $policy;

        $decisions = self::raceWith(PackagePermissions::GUARDRAIL_MANAGE, $rewrite);

        self::assertSame(GrantOutcome::GRANTED, self::service()->set($policy, null, ActingContext::for($actor)));
        self::assertSame([true, true], $decisions->getArrayCopy());
        self::assertSame(1, DB::table('guardrails')->count());
        self::assertStringContainsString('posts:edit', self::documentOf($policy));
    }

    /**
     * The exemption from the guardrail stage covers exactly
     * `authorization:guardrail.manage`, and only the guardrails: a guardrail
     * that does not allow the right never blocks it, but the actor's own deny
     * of it, a boundary that does not allow it and a cap of the call still
     * refuse, and the impersonation right, decided alongside it, stays capped
     * by the guardrails.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheExemptionCoversOnlyTheGuardrailRight(): void
    {
        $actor  = self::manager();
        $policy = self::rail('cap');
        $other  = self::rail('other');

        DB::table('guardrails')->insert(['policy_id' => self::rail('blocking')->getKey()]);

        self::assertSame(GrantOutcome::GRANTED, self::service()->set($policy, null, ActingContext::for($actor)));

        $impersonated = ActingContext::for($actor)->impersonatedBy(new Reference('support', '9'));

        $actor->givePermission(Permission::query()->create(['name' => PackagePermissions::ADMINISTRATION_IMPERSONATED]));

        self::assertRefusedAs('administration.impersonating', static fn (): GrantOutcome => self::service()->set($other, null, $impersonated));
        self::assertRefusedAs(GuardrailException::class, static fn (): GrantOutcome => self::service()->set($other, null, ActingContext::for($actor)->capped(['posts:*'])));

        $bounded = StubIdentity::query()->create(['id' => 'bounded']);

        $bounded->givePermission(Permission::query()->firstOrCreate(['name' => PackagePermissions::GUARDRAIL_MANAGE]));
        BoundaryService::instance()?->set($bounded, self::policy('bound', [['effect' => 'allow', 'actions' => ['posts:*']]]));

        self::assertRefusedAs(GuardrailException::class, static fn (): GrantOutcome => self::service()->set($other, null, ActingContext::for($bounded)));

        $denied = StubIdentity::query()->create(['id' => 'denied']);

        $denied->givePermission(Permission::query()->firstOrCreate(['name' => PackagePermissions::GUARDRAIL_MANAGE]));
        $denied->attachPolicy(self::policy('deny', [['effect' => 'deny', 'actions' => [PackagePermissions::GUARDRAIL_MANAGE]]]));

        self::assertRefusedAs(GuardrailException::class, static fn (): GrantOutcome => self::service()->set($other, null, ActingContext::for($denied)));
        self::assertSame(2, DB::table('guardrails')->count());
    }

    /**
     * A policy in use as a guardrail is never edited or deleted, through the
     * policy service, trusted or delegated, or through the model, until every
     * guardrail it is has been removed (an invariant of delegated
     * administration).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardrailsPolicyIsNeverEditedOrDeleted(): void
    {
        $actor   = self::manager();
        $policy  = self::policy('cap', [['effect' => 'allow', 'actions' => ['*']]]);
        $admin   = StubIdentity::query()->create(['id' => 'editor', 'name' => 'editor']);
        $context = ActingContext::for($admin);

        foreach ([PackagePermissions::POLICY_UPDATE, PackagePermissions::POLICY_DELETE, 'posts:*'] as $action) {
            $admin->givePermission(Permission::query()->firstOrCreate(['name' => $action]));
        }

        self::service()->set($policy, null, ActingContext::for($actor));

        $document = ['statements' => [['effect' => 'allow', 'actions' => ['posts:edit']]]];
        $policies = PolicyService::instance();

        self::assertNotNull($policies);
        self::assertRefusedAs(GuardrailException::class, static fn (): Policy => $policies->rewrite($policy, $document));
        self::assertRefusedAs(GuardrailException::class, static fn (): Policy => $policies->rewrite($policy, $document, $context));
        self::assertRefusedAs(GuardrailException::class, static fn () => $policies->delete($policy));
        self::assertRefusedAs(GuardrailException::class, static fn () => $policies->delete($policy, $context));
        self::assertRefusedAs(GuardrailException::class, static fn (): bool => self::stored($policy)->forceFill(['description' => 'edited'])->save());
        self::assertRefusedAs(GuardrailException::class, static fn (): ?bool => self::stored($policy)->delete());

        self::assertTrue(self::service()->remove($policy, null, ActingContext::for($actor)));

        $policies->rewrite(self::stored($policy), $document);

        self::assertStringContainsString('posts:edit', self::documentOf($policy));
    }

    /**
     * A tenant's policy is set on that tenant or a tenant below it, and refused
     * on the platform or any other tenant, before anything is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsPolicyIsSetOnlyOnItsTenantAndBelow(): void
    {
        [$org, $account, $other] = \array_map(self::createTenant(...), ['org', 'account', 'other']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($account), Reference::of($org)));

        $actor  = self::manager();
        $policy = self::rail('owned', ['tenant_type' => $org->getMorphClass(), 'tenant_id' => 'org']);

        self::assertSame(GrantOutcome::GRANTED, self::service()->set($policy, $org, ActingContext::for($actor)));
        self::assertSame(GrantOutcome::GRANTED, self::service()->set($policy, $account, ActingContext::for($actor)));

        foreach ([null, $other] as $tenant) {
            try {
                self::service()->set($policy, $tenant, ActingContext::for($actor));
                self::fail('The tenant\'s policy was set outside its tenant.');
            } catch (GrantScopeMismatchException) {
                // Expected.
            }
        }

        self::assertSame(2, DB::table('guardrails')->count());
    }

    /**
     * An inline policy, a policy naming principals and a policy whose row is
     * gone are each refused before anything is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesWhatCannotBeAGuardrail(): void
    {
        $actor  = self::manager();
        $inline = $actor->createInlinePolicy('mine', ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]);
        $named  = self::policy('named', [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]]);

        $refusals = [
            [static fn () => self::service()->set($inline, null, ActingContext::for($actor)), GuardrailException::class, 'Inline policy \'mine\''],
            [static fn () => self::service()->set($named, null, ActingContext::for($actor)), ResourcePolicyException::class, 'Policy \'named\''],
            [static fn () => self::service()->set(new Policy(['name' => 'unsaved']), null, ActingContext::for($actor)), InvalidGrantTargetException::class, ''],
        ];

        foreach ($refusals as [$call, $class, $message]) {
            try {
                $call();
                self::fail("{$class} was not thrown.");
            } catch (\Throwable $exception) {
                self::assertInstanceOf($class, $exception);
                self::assertStringContainsString($message, $exception->getMessage());
            }
        }

        self::assertSame(0, DB::table('guardrails')->count());
        self::assertFalse(self::service()->remove(new Policy(['name' => 'unsaved']), null, ActingContext::for($actor)));
    }

    /**
     * The guardrail's events are dispatched once the enclosing transaction
     * commits, each call an operation of its own, and never when it rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDispatchesOnlyOnceTheWriteCommits(): void
    {
        $actor  = self::manager();
        $policy = self::rail('cap');

        Event::fake([GuardrailSet::class, GuardrailRemoved::class]);

        try {
            DB::transaction(static function () use ($actor, $policy): void {
                self::service()->set($policy, null, ActingContext::for($actor));

                self::assertSame([], self::dispatchedEvents(GuardrailSet::class));

                throw new \RuntimeException('roll back');
            });
        } catch (\RuntimeException) {
            // Expected.
        }

        self::assertSame([], self::dispatchedEvents(GuardrailSet::class));
        self::assertSame(0, DB::table('guardrails')->count());

        DB::transaction(static function () use ($actor, $policy): void {
            self::service()->set($policy, null, ActingContext::for($actor));
            self::service()->remove($policy, null, ActingContext::for($actor));

            self::assertSame([], self::dispatchedEvents(GuardrailSet::class));
            self::assertSame([], self::dispatchedEvents(GuardrailRemoved::class));
        });

        self::assertCount(1, self::dispatchedEvents(GuardrailSet::class));
        self::assertCount(1, self::dispatchedEvents(GuardrailRemoved::class));
        self::assertNotSame(self::dispatchedEvents(GuardrailSet::class)[0]->operation->id, self::dispatchedEvents(GuardrailRemoved::class)[0]->operation->id);
    }

    /**
     * A guardrail whose row a concurrent change keeps from being read back,
     * even once the write is tried again, is refused, naming the scope: nothing
     * is reported set and no `GuardrailSet` is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardrailThatIsNotWrittenIsRefused(): void
    {
        $tenant = self::createTenant('tenant-a');
        $actor  = self::manager();
        $policy = self::rail('cap');

        self::service()->set($policy, null, ActingContext::for($actor));
        self::service()->set($policy, $tenant, ActingContext::for($actor));

        foreach ([[null, 'guardrail on the platform'], [$tenant, 'guardrail on ' . $tenant->getMorphClass() . ':tenant-a']] as [$scope, $named]) {
            $row = (array) DB::table('guardrails')->where('tenant_id', $scope?->getKey())->sole();

            self::churn($row);

            Event::fake([GuardrailSet::class]);

            try {
                self::service()->set($policy, $scope, ActingContext::for($actor));
                self::fail('The unwritten guardrail was reported set.');
            } catch (UnwrittenGrantException $exception) {
                self::assertSame($named, $exception->getGrant());
            }

            self::assertSame([], self::dispatchedEvents(GuardrailSet::class));

            DB::table('guardrails')->insertOrIgnore($row);
        }
    }

    /**
     * Return the policy as stored, read afresh.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function stored(Policy $policy): Policy
    {
        return Policy::query()->whereKey($policy->getKey())->firstOrFail();
    }

    /**
     * Return the policy's document as stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return string
     */
    private static function documentOf(Policy $policy): string
    {
        $document = DB::table('policies')->where('id', $policy->getKey())->value('document');

        return \is_string($document) ? $document : '';
    }

    /**
     * Assert the call is refused with the exception class, or as the reason of
     * an `AuthorizationException`.
     *
     * @param  string  $refusal
     * @param  \Closure(): mixed  $call
     * @return void
     */
    private static function assertRefusedAs(string $refusal, \Closure $call): void
    {
        try {
            $call();
        } catch (AuthorizationException $exception) {
            self::assertSame($refusal, $exception->getReason()->value);

            return;
        } catch (\Throwable $exception) {
            self::assertTrue(\is_a($exception, $refusal), 'The call was refused with ' . $exception::class . '.');

            return;
        }

        self::fail('The call was not refused.');
    }

    /**
     * Interleave a concurrent change with each write of the guardrail row: it
     * is removed once each of the first two inserts is ignored, and put back
     * once the first locking read of it runs, so neither insert writes a row
     * and no read finds one. Only the writer's own read of the row puts it
     * back, never the actor's check, which reads the guardrails too.
     *
     * @param  array<string, mixed>  $row
     * @return void
     */
    private static function churn(array $row): void
    {
        $removals = new \ArrayObject;
        $restored = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($row, $removals, $restored): void {
            $sql = \strtolower($query->sql);

            if (\str_starts_with($sql, 'select exists') && \str_contains($sql, 'guardrails') && $restored->count() < 1) {
                $restored->append(true);
                DB::table('guardrails')->insert($row);
            }

            if (!self::isIgnorableInsert($sql) || $removals->count() >= 2) {
                return;
            }

            $removals->append(true);
            self::remove($row);
        });
    }

    /**
     * Determine whether the statement is an insert-or-ignore into the
     * guardrails, whatever the driver.
     *
     * @param  string  $sql
     * @return bool
     */
    private static function isIgnorableInsert(string $sql): bool
    {
        return \str_starts_with($sql, 'insert') && \str_contains($sql, 'guardrails') && (\str_contains($sql, ' ignore') || \str_contains($sql, 'on conflict'));
    }

    /**
     * Remove the guardrail row.
     *
     * @param  array<string, mixed>  $row
     * @return void
     */
    private static function remove(array $row): void
    {
        $query = DB::table('guardrails')->where('policy_id', $row['policy_id']);

        $row['tenant_id'] === null ? $query->whereNull('tenant_id') : $query->where('tenant_id', $row['tenant_id']);

        $query->delete();
    }

    /**
     * Return an identity that holds the right to manage guardrails
     * platform-wide.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function manager(): StubIdentity
    {
        $actor = StubIdentity::create(['id' => 'admin-1']);

        $actor->givePermission(Permission::create(['name' => PackagePermissions::GUARDRAIL_MANAGE]));

        return $actor;
    }

    /**
     * Return the guardrail service, as the container binds it.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GuardrailService
     */
    private static function service(): GuardrailService
    {
        $service = GuardrailService::instance();

        self::assertInstanceOf(GuardrailService::class, $service);

        return $service;
    }

    /**
     * Create a guardrail policy allowing `posts:read` alone, with the
     * attributes.
     *
     * @param  string  $name
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function rail(string $name, array $attributes = []): Policy
    {
        return self::policy($name, [['effect' => 'allow', 'actions' => ['posts:read']]], $attributes);
    }

    /**
     * Create a policy of the statements, with the attributes.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, array $statements, array $attributes = []): Policy
    {
        return Policy::create(['name' => $name, ...$attributes, 'document' => ['statements' => $statements]]);
    }
}
