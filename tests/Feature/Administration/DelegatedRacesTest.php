<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\AuthorityRows;
use SineMacula\Laravel\Authorization\Administration\ConflictRetries;
use SineMacula\Laravel\Authorization\Administration\DependencyPins;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions as Actions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\RacesDelegatedCalls;
use Tests\Concerns\ReportsEveryDecision;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Races between a delegated decision and the write it allows (AUTHZ-11.1, the
 * concurrency protocol): a concurrent revocation of the actor's authority, a
 * role that grows, a policy rewritten, a resource policy naming a granted role
 * attached and a tenant moved, each landing after the decision and before the
 * write, and a rank or a document changed between the service's read of a
 * record and its lock, have the operation tried again and decided on what was
 * committed, so it is refused; a change that alters nothing the operation
 * relies on is tried again and made; and one that lands on every try is refused
 * as `administration.conflict`, recorded and reported as the actor's refusal.
 * Each race is simulated inside the operation's try, as the reads that follow
 * it would see a concurrent commit, so the version check runs on SQLite as on
 * PostgreSQL and MySQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DependencyPins::class)]
#[CoversClass(AuthorityRows::class)]
#[CoversClass(ConflictRetries::class)]
final class DelegatedRacesTest extends TestCase
{
    use ActsAsTenant, RacesDelegatedCalls, ReportsEveryDecision;

    /**
     * Report every decision, allows included: these tests observe the decisions
     * each call makes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->reportEveryDecision();
    }

    /**
     * The actor's authority revoked between the decision and the write has the
     * grant tried again, and refused, as the actor no longer holds what it
     * hands out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConcurrentRevocationOfTheActorIsRefusedOnTheRetry(): void
    {
        $actor     = self::actor('admin', [Actions::PERMISSION_GRANT, 'posts:edit']);
        $user      = self::user('user');
        $admin     = self::model($actor);
        $decisions = self::raceWith(Actions::PERMISSION_GRANT, static fn (): int => self::grants()->revokePermission($admin, 'posts:edit'));
        $changes   = self::recordChanges();

        $refusal = self::refusalOf(static fn (): GrantOutcome => self::grants()->grantPermission($user, 'posts:edit', actor: $actor));

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $refusal->getReason());
        self::assertSame([true, false], $decisions->getArrayCopy());
        self::assertFalse(self::holds($user, 'posts:edit'));
        self::assertNotContains(PermissionGranted::class, $changes->getArrayCopy());
    }

    /**
     * A role given a permission the actor does not hold between the decision
     * and the write has the role grant tried again, and refused, as the role
     * now hands out what the actor cannot.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleThatGrowsIsRefusedOnTheRetry(): void
    {
        $actor = self::actor('admin', [Actions::ROLE_GRANT, 'posts:read']);
        $user  = self::user('user');
        $role  = Role::query()->create(['name' => 'reader']);

        self::roles()->grantPermission($role, self::permission('posts:read'));

        $decisions = self::raceWith(Actions::ROLE_GRANT, static fn (): GrantOutcome => self::roles()->grantPermission($role, self::permission('posts:delete')));

        $refusal = self::refusalOf(static fn (): GrantOutcome => self::grants()->grantRole($user, $role, actor: $actor));

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $refusal->getReason());
        self::assertSame([true, false], $decisions->getArrayCopy());
        self::assertSame(0, DB::table('authorizable_roles')->where('authorizable_id', 'user')->count());
    }

    /**
     * A policy rewritten to allow what the actor does not hold between the
     * decision and the write has the attachment tried again, and refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyRewrittenIsRefusedOnTheRetry(): void
    {
        $actor  = self::actor('admin', [Actions::POLICY_ATTACH, 'posts:read']);
        $user   = self::user('user');
        $policy = self::document('readers', ['posts:read']);

        // A concurrent call reads the policy afresh, as another process would.
        $document  = ['statements' => [['effect' => 'allow', 'actions' => ['posts:delete']]]];
        $rewrite   = static fn (): Policy => self::policies()->rewrite(Policy::query()->whereKey($policy->getKey())->firstOrFail(), $document);
        $decisions = self::raceWith(Actions::POLICY_ATTACH, $rewrite);

        $refusal = self::refusalOf(static fn (): GrantOutcome => self::grants()->attachPolicy($user, $policy, actor: $actor));

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $refusal->getReason());
        self::assertSame([true, false], $decisions->getArrayCopy());
        self::assertSame(0, DB::table('authorizable_policies')->where('authorizable_id', 'user')->count());
    }

    /**
     * A tenant moved out of the actor's reach between the decision and the
     * write, and reported with `treeChanged()`, has the grant tried again in
     * the tree as moved, and refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantMovedOutOfReachIsRefusedOnTheRetry(): void
    {
        [$parent, $other, $child] = \array_map(self::createTenant(...), ['parent', 'other', 'child']);

        $tree = (new StubTenantTree)->put(Reference::of($child), Reference::of($parent))->put(Reference::of($other), null);

        $this->app?->instance(TenantTree::class, $tree);

        $actor = self::actor('admin', [], $parent);
        $user  = self::user('user');

        $this->actAsTenant($parent);

        $move = static function () use ($tree, $child, $other): void {
            $tree->put(Reference::of($child), Reference::of($other));

            Authorization::treeChanged($child);
        };

        $decisions = self::raceWith(Actions::PERMISSION_GRANT, $move);

        $refusal = self::refusalOf(static fn (): GrantOutcome => self::grants()->grantPermission($user, 'posts:edit', actor: $actor, tenant: $child));

        self::assertSame(DecisionReason::TENANT_SCOPE, $refusal->getReason());
        self::assertSame([true, false], $decisions->getArrayCopy());
        self::assertFalse(self::holds($user, 'posts:edit'));
    }

    /**
     * A concurrent change to something the operation relies on that leaves its
     * authority as it was has the operation tried again and made, once, its
     * change event dispatched once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHarmlessRaceIsTriedAgainAndMade(): void
    {
        $actor     = self::actor('admin', [Actions::PERMISSION_GRANT, 'posts:edit']);
        $user      = self::user('user');
        $admin     = self::model($actor);
        $comments  = self::permission('comments:read');
        $decisions = self::raceWith(Actions::PERMISSION_GRANT, static fn (): GrantOutcome => self::grants()->grantPermission($admin, $comments));

        /** @var \ArrayObject<int, string> $granted */
        $granted = new \ArrayObject;

        Event::listen(PermissionGranted::class, static function (PermissionGranted $event) use ($granted): void {
            $granted->append($event->grantee->id);
        });

        self::assertSame(GrantOutcome::GRANTED, self::grants()->grantPermission($user, 'posts:edit', actor: $actor));
        self::assertSame([true, true], $decisions->getArrayCopy());
        self::assertTrue(self::holds($user, 'posts:edit'));
        self::assertSame(['admin', 'user'], $granted->getArrayCopy());
    }

    /**
     * An operation that conflicts on every try is tried again
     * `authorization.administration.retries` times, then refused as
     * `administration.conflict` at the administration stage, writing nothing;
     * with no retries it is refused on its first conflict.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationThatConflictsOnEveryTryIsRefusedAsAConflict(): void
    {
        $actor = self::actor('admin', [Actions::PERMISSION_GRANT, 'posts:edit']);
        $user  = self::user('user');
        $admin = self::model($actor);
        $touch = static fn (): int => DB::table('authorizable_permissions')->where('authorizable_id', $admin->getKey())->update(['updated_at' => '2001-01-01 00:00:00']);

        $decisions = self::raceWith(Actions::PERMISSION_GRANT, $touch, true);
        $changes   = self::recordChanges();
        $refusal   = self::refusalOf(static fn (): GrantOutcome => self::grants()->grantPermission($user, 'posts:edit', actor: $actor));

        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $refusal->getReason());
        self::assertSame(DecisionStage::ADMINISTRATION, $refusal->getDecision()?->stage);
        self::assertSame([...\array_fill(0, 1 + ConflictRetries::DEFAULT_RETRIES, true), false], $decisions->getArrayCopy());
        self::assertFalse(self::holds($user, 'posts:edit'));
        self::assertSame([], $changes->getArrayCopy());
    }

    /**
     * The refusal of an operation that conflicted on every try is recorded and
     * reported as any refusal is: the acting subject's `DecisionEvaluated` and
     * `AuthorizationFailed`, on the operation resource, under the operation's
     * action, as `administration.conflict`, after the decisions of every try
     * under the same operation id.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheConflictRefusalIsRecordedAndReported(): void
    {
        $actor = self::actor('admin', [Actions::PERMISSION_GRANT, 'posts:edit']);
        $user  = self::user('user');
        $admin = self::model($actor);
        $touch = static fn (): int => DB::table('authorizable_permissions')->where('authorizable_id', $admin->getKey())->update(['updated_at' => '2001-01-01 00:00:00']);

        self::raceWith(Actions::PERMISSION_GRANT, $touch, true);

        /** @var \ArrayObject<int, \SineMacula\Laravel\Authorization\Events\DecisionEvaluated> $evaluated */
        $evaluated = new \ArrayObject;

        /** @var \ArrayObject<int, \SineMacula\Laravel\Authorization\Events\AuthorizationFailed> $failed */
        $failed = new \ArrayObject;

        Event::listen(DecisionEvaluated::class, static fn (DecisionEvaluated $event) => $event->action === Actions::PERMISSION_GRANT ? $evaluated->append($event) : null);
        Event::listen(AuthorizationFailed::class, static fn (AuthorizationFailed $event) => $failed->append($event));

        $refusal = self::refusalOf(static fn (): GrantOutcome => self::grants()->grantPermission($user, 'posts:edit', actor: $actor));

        [$first] = $evaluated->getArrayCopy();
        [$fail]  = $failed->getArrayCopy();
        $last    = \array_slice($evaluated->getArrayCopy(), -1)[0];

        self::assertCount(1, $failed);
        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $fail->reason);
        self::assertSame(Actions::PERMISSION_GRANT, $fail->action);
        self::assertEquals(Reference::of($admin), $fail->subject);
        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $last->reason);
        self::assertEquals(Reference::of($admin), $last->subject);
        self::assertSame($fail->resource, $last->resource);
        self::assertSame($first->resource, $last->resource);
        self::assertStringStartsWith('authorization:operation:', (string) $last->resource);
        self::assertSame($refusal->getDecision(), Authorization::lastDecision());
    }

    /**
     * With no retries configured, the first conflict is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoRetriesTheFirstConflictIsRefused(): void
    {
        config(['authorization.administration.retries' => 0]);

        $actor = self::actor('admin', [Actions::PERMISSION_GRANT, 'posts:edit']);
        $user  = self::user('user');
        $admin = self::model($actor);

        $decisions = self::raceWith(Actions::PERMISSION_GRANT, static fn (): int => self::grants()->revokePermission($admin, 'posts:edit'));
        $refusal   = self::refusalOf(static fn (): GrantOutcome => self::grants()->grantPermission($user, 'posts:edit', actor: $actor));

        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $refusal->getReason());
        self::assertSame([true, false], $decisions->getArrayCopy());
    }

    /**
     * A role whose rank rises between the service's read of it and its lock is
     * read again under the lock, so the grant is tried again and refused on the
     * rank stored, never decided on the rank the service read first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARankChangedBeforeTheLockIsTriedAgainAndRefused(): void
    {
        $actor = self::actor('admin', [Actions::ROLE_GRANT]);
        $user  = self::user('user');
        $role  = Role::query()->create(['name' => 'junior', 'rank' => 10]);
        $raise = static fn (): int => DB::table('roles')->where('id', $role->getKey())->update(['rank' => 1]);
        $raced = self::raceOnQuery('/^select \* from roles where roles\.id = \? limit 1$/', $raise);

        $refusal = self::refusalOf(static fn (): GrantOutcome => self::grants()->grantRole($user, $role, actor: $actor));

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $refusal->getReason());
        self::assertCount(1, $raced);
        self::assertSame(0, DB::table('authorizable_roles')->where('authorizable_id', 'user')->count());
    }

    /**
     * A policy rewritten between the service's read of it and its lock is read
     * again under the lock, so the attachment is tried again and refused on the
     * document stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADocumentChangedBeforeTheLockIsTriedAgainAndRefused(): void
    {
        $actor   = self::actor('admin', [Actions::POLICY_ATTACH, 'posts:read']);
        $user    = self::user('user');
        $policy  = self::document('readers', ['posts:read']);
        $widened = ['name' => 'readers', 'statements' => [['effect' => 'allow', 'actions' => ['posts:delete']]]];
        $rewrite = static fn (): int => DB::table('policies')->where('id', $policy->getKey())->update(['document' => \json_encode($widened)]);
        $raced   = self::raceOnQuery('/^select \* from policies where policies\.id = \? limit 1$/', $rewrite);

        $refusal = self::refusalOf(static fn (): GrantOutcome => self::grants()->attachPolicy($user, $policy, actor: $actor));

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $refusal->getReason());
        self::assertCount(1, $raced);
        self::assertSame(0, DB::table('authorizable_policies')->where('authorizable_id', 'user')->count());
    }

    /**
     * A resource policy naming a role, allowing what the actor does not hold,
     * attached between the decision of a grant of that role and the write, has
     * the grant tried again, and refused, as the role now hands out what the
     * actor cannot.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourcePolicyNamingTheRoleAttachedMeanwhileIsRefusedOnTheRetry(): void
    {
        $actor  = self::actor('admin', [Actions::ROLE_GRANT]);
        $user   = self::user('user');
        $role   = Role::query()->create(['name' => 'sharer']);
        $allow  = ['effect' => 'allow', 'actions' => ['posts:delete'], 'principals' => ['role:' . $role->id]];
        $policy = Policy::query()->create(['name' => 'sharing', 'document' => ['statements' => [$allow]]]);
        $attach = static fn (): bool => DB::table('resource_policies')->insert(['policy_id' => $policy->getKey(), 'resource_type' => 'post', 'resource_id' => null]);

        $decisions = self::raceWith(Actions::ROLE_GRANT, $attach);

        $refusal = self::refusalOf(static fn (): GrantOutcome => self::grants()->grantRole($user, $role, actor: $actor));

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $refusal->getReason());
        self::assertSame([true, false], $decisions->getArrayCopy());
        self::assertSame(0, DB::table('authorizable_roles')->where('authorizable_id', 'user')->count());
    }

    /**
     * A trusted call runs once, under no protocol: a change landing between its
     * writes is never noticed, and nothing is tried again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATrustedCallIsNeverTriedAgain(): void
    {
        $user  = self::user('user');
        $tries = new \ArrayObject;

        self::permission('posts:edit');

        $outcome = OperationScope::run(
            Operation::begin(),
            static function () use ($tries, $user): GrantOutcome {
                $tries->append(true);

                self::assertNull(OperationScope::pins());

                return self::grants()->grantPermission($user, 'posts:edit');
            },
        );

        self::assertSame(GrantOutcome::GRANTED, $outcome);
        self::assertCount(1, $tries);
    }

    /**
     * Run the call and return the `AuthorizationException` it is refused with.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function refusalOf(\Closure $call): AuthorizationException
    {
        try {
            $call();
        } catch (AuthorizationException $refusal) {
            return $refusal;
        }

        self::fail('The call was not refused.');
    }

    /**
     * Return the acting context of a new identity of rank 1 granted each
     * permission, platform-wide or in the tenant given, its subtree included.
     *
     * @param  string  $id
     * @param  list<string>  $permissions
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Administration\ActingContext
     *
     * @throws \Throwable
     */
    private static function actor(string $id, array $permissions, ?StubTenant $tenant = null): ActingContext
    {
        $actor = self::user($id, 1);

        foreach ($tenant === null ? $permissions : [Actions::PERMISSION_GRANT, 'posts:edit'] as $name) {
            self::grants()->grantPermission($actor, self::permission($name), tenant: $tenant);
        }

        return ActingContext::for($actor);
    }

    /**
     * Return the identity behind the acting context.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function model(ActingContext $actor): StubIdentity
    {
        /** @var \Tests\Feature\Stubs\StubIdentity */
        return $actor->subject->subject;
    }

    /**
     * Return a new identity, holding a platform role of the rank, or none for
     * null.
     *
     * @param  string  $id
     * @param  int|null  $rank
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function user(string $id, ?int $rank = null): StubIdentity
    {
        $user = StubIdentity::query()->create(['id' => $id]);

        if ($rank !== null) {
            self::grants()->grantRole($user, Role::query()->firstOrCreate(['name' => 'rank-' . $rank], ['rank' => $rank]));
        }

        return $user;
    }

    /**
     * Determine whether the identity holds the permission directly, as stored.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  string  $permission
     * @return bool
     */
    private static function holds(StubIdentity $user, string $permission): bool
    {
        return DB::table('authorizable_permissions')
            ->join('permissions', 'permissions.id', '=', 'authorizable_permissions.permission_id')
            ->where('authorizable_id', $user->getKey())
            ->where('permissions.name', $permission)
            ->exists();
    }

    /**
     * Return the permission of the name, created when there is none.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function permission(string $name): Permission
    {
        return Permission::query()->firstOrCreate(['name' => $name]);
    }

    /**
     * Return a new policy allowing the actions.
     *
     * @param  string  $name
     * @param  list<string>  $actions
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function document(string $name, array $actions): Policy
    {
        return Policy::query()->create(['name' => $name, 'document' => ['statements' => [['effect' => 'allow', 'actions' => $actions]]]]);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        /** @var \SineMacula\Laravel\Authorization\Services\GrantService */
        return GrantService::instance();
    }

    /**
     * Return the role service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleService
     */
    private static function roles(): RoleService
    {
        /** @var \SineMacula\Laravel\Authorization\Services\RoleService */
        return RoleService::instance();
    }

    /**
     * Return the policy service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\PolicyService
     */
    private static function policies(): PolicyService
    {
        /** @var \SineMacula\Laravel\Authorization\Services\PolicyService */
        return PolicyService::instance();
    }
}
