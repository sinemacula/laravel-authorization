<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\Identity\BoundaryRemoved;
use SineMacula\Laravel\Authorization\Events\Identity\BoundarySet;
use SineMacula\Laravel\Authorization\Exceptions\BoundaryException;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException;
use SineMacula\Laravel\Authorization\Exceptions\UnwrittenGrantException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\AssertsDelegatedRefusals;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\InterleavesWrites;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\VanishedPolicy;
use Tests\TestCase;

/**
 * Feature tests for `BoundaryService`, which sets, replaces and removes the
 * permission boundaries of principals and identities.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(BoundaryService::class)]
final class BoundaryServiceTest extends TestCase
{
    use ActsAsAdministrator, ActsAsTenant, AssertsDelegatedRefusals, CatchesRefusals, ComparesReferences, InterleavesWrites, ReadsDispatchedEvents;

    /**
     * The service is bound once in the container.
     *
     * @return void
     */
    public function testIsBoundAsASingleton(): void
    {
        self::assertInstanceOf(BoundaryService::class, self::service());
        self::assertSame(self::service(), self::service());
    }

    /**
     * A boundary is set platform-wide by default, as trusted work its row
     * recording no actor, and reported once with the operation, the grantee,
     * the policy and the scope, naming no policy replaced.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSetsABoundary(): void
    {
        Event::fake([BoundarySet::class]);

        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::cap('read-only');

        self::assertSame(GrantOutcome::GRANTED, self::service()->set($user, $policy));

        $row = (array) DB::table('authorizable_boundaries')->sole();

        self::assertSame([$user->getMorphClass(), 'user-1', null, null, null, null], [
            $row['authorizable_type'], $row['authorizable_id'], $row['tenant_type'], $row['tenant_id'], $row['granted_by_type'], $row['granted_by_id'],
        ]);
        self::assertSame($policy->id, $row['policy_id']);
        self::assertTrue((bool) $row['include_subtree']);

        $events = self::dispatchedEvents(BoundarySet::class);

        self::assertCount(1, $events);
        self::assertTrue(self::refersTo($events[0]->grantee, $user));
        self::assertTrue(self::refersTo($events[0]->policy, $policy));
        self::assertNull($events[0]->operation->actor);
        self::assertSame([PackagePermissions::BOUNDARY_SET], $events[0]->operation->actions);
        self::assertSame('read-only', $events[0]->name);
        self::assertNull($events[0]->scope->tenant);
        self::assertNull($events[0]->scope->application);
        self::assertTrue($events[0]->scope->includeSubtree);
        self::assertNull($events[0]->previous);
    }

    /**
     * Setting the boundary the grantee has in the scope changes nothing and
     * reports nothing; another reach changes the reach alone, and another
     * policy replaces it, each reported, the replacement naming the policy it
     * replaced; the grantee keeps one boundary in the scope throughout.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSettingAgainChangesTheReachOrReplacesTheBoundary(): void
    {
        $tenant = self::createTenant('tenant-a');
        $user   = StubIdentity::create(['id' => 'user-1']);
        $first  = self::cap('first');
        $second = self::cap('second');

        self::service()->set($user, $first, $tenant);

        Event::fake([BoundarySet::class]);

        self::assertSame(GrantOutcome::UNCHANGED, self::service()->set($user, $first, $tenant));
        self::assertSame([], self::dispatchedEvents(BoundarySet::class));
        self::assertSame(GrantOutcome::REACH_CHANGED, self::service()->set($user, $first, $tenant, false));
        self::assertFalse((bool) DB::table('authorizable_boundaries')->value('include_subtree'));
        self::assertSame(GrantOutcome::REPLACED, self::service()->set($user, $second, $tenant, false));

        $row = (array) DB::table('authorizable_boundaries')->sole();

        self::assertSame($second->id, $row['policy_id']);
        self::assertNull($row['granted_by_id']);

        $events = self::dispatchedEvents(BoundarySet::class);

        self::assertCount(2, $events);
        self::assertNull($events[0]->previous);
        self::assertFalse($events[0]->scope->includeSubtree);
        self::assertTrue(self::refersTo($events[0]->scope->tenant, $tenant));
        self::assertTrue(self::refersTo($events[1]->policy, $second));
        self::assertTrue(self::refersTo($events[1]->previous, $first));
        self::assertSame('second', $events[1]->name);
    }

    /**
     * A grantee has one boundary per scope: one platform-wide and one in a
     * tenant are two, and a platform-wide one always reaches below.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSetsOneBoundaryPerScope(): void
    {
        $tenant = self::createTenant('tenant-a');
        $user   = StubIdentity::create(['id' => 'user-1']);

        self::service()->set($user, self::cap('platform'), includeSubtree: false);
        self::service()->set($user, self::cap('tenant'), $tenant);
        self::service()->set(StubIdentity::create(['id' => 'user-2']), self::cap('other'));

        self::assertSame(3, DB::table('authorizable_boundaries')->count());
        self::assertTrue((bool) DB::table('authorizable_boundaries')->whereNull('tenant_id')->where('authorizable_id', 'user-1')->value('include_subtree'));
    }

    /**
     * A boundary is removed in the scope named, reported with the policy it was
     * and the reach it had; removing it elsewhere, or again, removes nothing
     * and reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesInTheScope(): void
    {
        $tenant = self::createTenant('tenant-a');
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::cap('tenant-cap');

        self::service()->set($user, $policy, $tenant, false);

        Event::fake([BoundaryRemoved::class]);

        self::assertFalse(self::service()->remove($user));
        self::assertTrue(self::service()->remove($user, $tenant));
        self::assertFalse(self::service()->remove($user, $tenant));
        self::assertSame(0, DB::table('authorizable_boundaries')->count());

        $events = self::dispatchedEvents(BoundaryRemoved::class);

        self::assertCount(1, $events);
        self::assertTrue(self::refersTo($events[0]->grantee, $user));
        self::assertTrue(self::refersTo($events[0]->policy, $policy));
        self::assertNull($events[0]->operation->actor);
        self::assertSame('tenant-cap', $events[0]->name);
        self::assertSame([PackagePermissions::BOUNDARY_REMOVE], $events[0]->operation->actions);
        self::assertTrue(self::refersTo($events[0]->scope->tenant, $tenant));
        self::assertFalse($events[0]->scope->includeSubtree);
    }

    /**
     * A delegated boundary change is decided under its action before anything
     * is written: setting a boundary, and removing one, widen authority, so an
     * actor allowed every action is refused as unprovable, or, removing a
     * tenant's boundary from the platform, as not its owner, and one without
     * the action as no match, or as out of scope for a tenant's boundary when
     * no tenant is active.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedBoundaryChangeIsRefused(): void
    {
        $tenant = self::createTenant('tenant-a');
        $admin  = self::administrator();
        $nobody = self::administrator([], 'nobody');
        $user   = StubIdentity::create(['id' => 'user-1']);
        $cap    = self::cap('cap');
        $other  = self::cap('other');

        $platform = StubIdentity::create(['id' => 'user-2']);

        self::service()->set($user, $cap, $tenant, false);
        self::service()->set($user, $cap);
        self::service()->set($platform, $cap);

        $unprovable = DecisionReason::ADMINISTRATION_UNPROVABLE;

        self::assertDelegatedRefusal($unprovable, static fn (): GrantOutcome => self::service()->set($user, $other, actor: $admin));
        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_OWNER, static fn (): bool => self::service()->remove($user, $tenant, $admin));
        self::assertDelegatedRefusal($unprovable, static fn (): bool => self::service()->remove($user, actor: $admin));
        self::assertDelegatedRefusal($unprovable, static fn (): int => self::service()->removeAll($platform, $admin));
        self::assertDelegatedRefusal(DecisionReason::NO_MATCH, static fn (): GrantOutcome => self::service()->set($user, $other, actor: $nobody));
        self::assertDelegatedRefusal(DecisionReason::TENANT_SCOPE, static fn (): bool => self::service()->remove($user, $tenant, $nobody));
        self::assertDelegatedRefusal(DecisionReason::NO_MATCH, static fn (): bool => self::service()->remove($user, actor: $nobody));
        self::assertDelegatedRefusal(DecisionReason::NO_MATCH, static fn (): int => self::service()->removeAll($platform, $nobody));
        self::assertSame([PackagePermissions::BOUNDARY_REMOVE], self::actionsDecided());
    }

    /**
     * A delegated removal of a boundary the grantee does not have is still
     * decided on its action, so an actor without it is refused whether or not
     * there is a boundary to remove, and one with it removes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedRemovalOfNothingIsStillDecided(): void
    {
        $actor  = self::administrator([PackagePermissions::BOUNDARY_REMOVE]);
        $nobody = self::administrator([], 'nobody');
        $user   = StubIdentity::create(['id' => 'user-1']);

        self::assertDelegatedRefusal(DecisionReason::NO_MATCH, static fn (): bool => self::service()->remove($user, actor: $nobody));
        self::assertDelegatedRefusal(DecisionReason::NO_MATCH, static fn (): int => self::service()->removeAll($user, $nobody));

        self::fakePackageEvents();

        self::assertFalse(self::service()->remove($user, actor: $actor));
        self::assertSame(0, self::service()->removeAll($user, $actor));
        self::assertSame([PackagePermissions::BOUNDARY_REMOVE, PackagePermissions::BOUNDARY_REMOVE], self::actionsDecided());
        self::assertSame([], self::changesDispatched());
    }

    /**
     * The delegated removal of a boundary whose policy can no longer be read is
     * refused before anything is decided or removed, since what it removes
     * cannot be named.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedRemovalOfABoundaryWhosePolicyIsGoneIsRefused(): void
    {
        $actor = self::administrator();
        $user  = StubIdentity::create(['id' => 'user-1']);

        self::service()->set($user, self::cap('cap'));

        config()->set('authorization.models.policy', VanishedPolicy::class);

        foreach ([static fn (): bool => self::service()->remove($user, actor: $actor), static fn (): int => self::service()->removeAll($user, $actor)] as $call) {
            self::assertInstanceOf(InvalidGrantTargetException::class, self::refusalOf($call));
            self::assertSame(1, DB::table('authorizable_boundaries')->count());
        }
    }

    /**
     * A grantee given by reference has its boundary set and removed as a
     * model's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTakesAGranteeByReference(): void
    {
        $reference = new Reference('member', 'm-1');

        self::assertSame(GrantOutcome::GRANTED, self::service()->set($reference, self::cap('cap')));
        self::assertSame('member', DB::table('authorizable_boundaries')->value('authorizable_type'));
        self::assertTrue(self::service()->remove($reference));
    }

    /**
     * Removing every boundary of a grantee inside an operation removes each, in
     * every scope, and returns an event for each, dispatching none itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesEveryBoundaryOfAGrantee(): void
    {
        $tenant = self::createTenant('tenant-a');
        $user   = StubIdentity::create(['id' => 'user-1']);

        self::service()->set($user, self::cap('platform'));
        self::service()->set($user, self::cap('tenant'), $tenant, false);
        self::service()->set(StubIdentity::create(['id' => 'user-2']), self::cap('other'));

        Event::fake([BoundaryRemoved::class]);

        $events = OperationScope::run(Operation::begin(), static fn (Operation $operation): array => BoundaryService::removeEverywhere(Reference::of($user), $operation));
        $scopes = \array_map(static fn (BoundaryRemoved $event): array => [$event->name, $event->scope->tenant?->id, $event->scope->includeSubtree], $events);

        \sort($scopes);

        self::assertSame([['platform', null, true], ['tenant', 'tenant-a', false]], $scopes);
        self::assertSame([], self::dispatchedEvents(BoundaryRemoved::class));
        self::assertSame(['user-2'], DB::table('authorizable_boundaries')->pluck('authorizable_id')->all());
    }

    /**
     * Removing all of a grantee's boundaries removes each, in every scope, in
     * one trusted operation, dispatching a `BoundaryRemoved` for each and
     * returning how many there were; a grantee with none removes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesAllOfAGranteesBoundaries(): void
    {
        $tenant = self::createTenant('tenant-a');
        $user   = StubIdentity::create(['id' => 'user-1']);

        self::service()->set($user, self::cap('platform'));
        self::service()->set($user, self::cap('tenant'), $tenant);
        self::service()->set(StubIdentity::create(['id' => 'user-2']), self::cap('other'));

        Event::fake([BoundaryRemoved::class]);

        self::assertSame(2, self::service()->removeAll(Reference::of($user)));

        $events = self::dispatchedEvents(BoundaryRemoved::class);
        $names  = \array_map(static fn (BoundaryRemoved $event): string => $event->name, $events);

        \sort($names);

        self::assertSame(['platform', 'tenant'], $names);
        self::assertSame($events[0]->operation->id, $events[1]->operation->id);
        self::assertTrue($events[0]->operation->isTrusted);
        self::assertSame([PackagePermissions::BOUNDARY_REMOVE], $events[0]->operation->actions);
        self::assertSame(['user-2'], DB::table('authorizable_boundaries')->pluck('authorizable_id')->all());
        self::assertSame(0, self::service()->removeAll($user));
        self::assertCount(2, self::dispatchedEvents(BoundaryRemoved::class));
    }

    /**
     * A policy one tenant owns is set as a boundary in that tenant by default,
     * and refused in any other.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsPolicyIsSetOnlyInItsTenant(): void
    {
        [$tenantA, $tenantB] = \array_map(self::createTenant(...), ['tenant-a', 'tenant-b']);

        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::cap('owned', ['tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => 'tenant-a']);

        self::service()->set($user, $policy);

        self::assertSame('tenant-a', DB::table('authorizable_boundaries')->value('tenant_id'));

        $this->expectException(GrantScopeMismatchException::class);

        self::service()->set($user, $policy, $tenantB);
    }

    /**
     * An inline policy, a policy naming principals, a policy whose row is gone,
     * and a grantee that is never a subject's principal or identity, a role, a
     * permission or a policy, by model or by reference, are each refused before
     * anything is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesWhatCannotBeABoundary(): void
    {
        $user       = StubIdentity::create(['id' => 'user-1']);
        $inline     = $user->createInlinePolicy('mine', ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]);
        $named      = self::policy('named', [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]]);
        $role       = Role::create(['name' => 'editor']);
        $permission = Permission::create(['name' => 'posts:read']);
        $policy     = self::cap('held');

        $refusals = [
            [static fn () => self::service()->set($user, $inline), BoundaryException::class, 'Inline policy \'mine\''],
            [static fn () => self::service()->set($user, $named), ResourcePolicyException::class, 'Policy \'named\''],
            [static fn () => self::service()->set($user, new Policy(['name' => 'unsaved'])), InvalidGrantTargetException::class, ''],
            [static fn () => self::service()->set($role, self::cap('cap')), BoundaryException::class, "boundary of role '{$role->id}'"],
            [static fn () => self::service()->set($permission, self::cap('cap-2')), BoundaryException::class, "boundary of permission '{$permission->id}'"],
            [static fn () => self::service()->set($policy, self::cap('cap-3')), BoundaryException::class, "boundary of policy '{$policy->id}'"],
            [static fn () => self::service()->set(Reference::of($permission), self::cap('cap-4')), BoundaryException::class, 'never a permission'],
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

        self::assertSame(0, DB::table('authorizable_boundaries')->count());
    }

    /**
     * A grantee that is not a saved model with a key, or a reference with a
     * type and a key, is refused before anything is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAGranteeWithoutAKey(): void
    {
        foreach ([new StubIdentity(['id' => 'unsaved']), new Reference('member', '')] as $grantee) {
            try {
                self::service()->set($grantee, self::cap('cap-' . \spl_object_id($grantee)));
                self::fail('The grantee was not refused.');
            } catch (InvalidGranteeException) {
                // Expected.
            }
        }

        $this->expectException(InvalidGranteeException::class);

        self::service()->remove(new Reference('', 'm-1'));
    }

    /**
     * The boundary's events are dispatched once the enclosing transaction
     * commits, and never when it rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDispatchesOnlyOnceTheWriteCommits(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::cap('cap');

        Event::fake([BoundarySet::class, BoundaryRemoved::class]);

        try {
            DB::transaction(static function () use ($user, $policy): void {
                self::service()->set($user, $policy);

                self::assertSame([], self::dispatchedEvents(BoundarySet::class));

                throw new \RuntimeException('roll back');
            });
        } catch (\RuntimeException) {
            // Expected.
        }

        self::assertSame([], self::dispatchedEvents(BoundarySet::class));
        self::assertSame(0, DB::table('authorizable_boundaries')->count());

        DB::transaction(static function () use ($user, $policy): void {
            self::service()->set($user, $policy);
            self::service()->remove($user);

            self::assertSame([], self::dispatchedEvents(BoundarySet::class));
            self::assertSame([], self::dispatchedEvents(BoundaryRemoved::class));
        });

        self::assertCount(1, self::dispatchedEvents(BoundarySet::class));
        self::assertCount(1, self::dispatchedEvents(BoundaryRemoved::class));
        self::assertNotSame(self::dispatchedEvents(BoundarySet::class)[0]->operation->id, self::dispatchedEvents(BoundaryRemoved::class)[0]->operation->id);
    }

    /**
     * A policy deleted while its boundary is written, which on MySQL leaves no
     * row once `INSERT IGNORE` turns the foreign key failure into a warning, is
     * refused as gone: nothing is reported set, no `BoundarySet` is dispatched,
     * and the boundary held before is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyDeletedWhileItIsWrittenIsRefused(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $held   = self::cap('held');
        $policy = self::cap('deleted');

        self::service()->set($user, $held);
        self::churn($policy->id);

        Event::fake([BoundarySet::class]);

        try {
            self::service()->set($user, $policy);
            self::fail('The deleted policy was set as a boundary.');
        } catch (InvalidGrantTargetException $exception) {
            self::assertSame('policy', $exception->getKind());
        }

        self::assertSame([], self::dispatchedEvents(BoundarySet::class));
        self::assertSame(1, DB::table('authorizable_boundaries')->count());
        self::assertEquals($held->id, DB::table('authorizable_boundaries')->value('policy_id'));
    }

    /**
     * A boundary whose row a concurrent change keeps from being written, even
     * once the write is tried again, is refused: nothing is reported set and no
     * `BoundarySet` is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundaryThatIsNotWrittenIsRefused(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        self::service()->set($user, self::cap('held'));
        self::churn();

        Event::fake([BoundarySet::class]);

        try {
            self::service()->set($user, self::cap('unwritten'));
            self::fail('The unwritten boundary was reported set.');
        } catch (UnwrittenGrantException $exception) {
            self::assertSame('boundary of ' . $user->getMorphClass() . ':user-1', $exception->getGrant());
        }

        self::assertSame([], self::dispatchedEvents(BoundarySet::class));
        self::assertSame(1, DB::table('authorizable_boundaries')->count());
    }

    /**
     * A grantee deleted takes its boundaries with it, each reported, so their
     * policies can be deleted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGranteeDeletedTakesItsBoundaries(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::cap('cap');

        self::service()->set($user, $policy);

        Event::fake([BoundaryRemoved::class]);

        $user->delete();

        self::assertSame(0, DB::table('authorizable_boundaries')->count());
        self::assertCount(1, self::dispatchedEvents(BoundaryRemoved::class));
        self::assertTrue($policy->delete());
    }

    /**
     * Interleave a concurrent change with each write of `user-1`'s boundary:
     * its row is removed once each insert is ignored, and put back once it is
     * read back, so neither insert writes a row, and the policy with the given
     * key, when one is given, is deleted with the first removal.
     *
     * @param  string|null  $deleted
     * @return void
     */
    private static function churn(?string $deleted = null): void
    {
        $row = (array) DB::table('authorizable_boundaries')->where('authorizable_id', 'user-1')->sole();

        self::interleaveWrites('authorizable_boundaries', static function () use ($deleted): void {
            DB::table('authorizable_boundaries')->where('authorizable_id', 'user-1')->delete();
            DB::table('policies')->where('id', $deleted)->delete();
        }, static function () use ($row): void {
            DB::table('authorizable_boundaries')->insert($row);
        }, 2, 1);
    }

    /**
     * Return the boundary service, as the container binds it.
     *
     * @return \SineMacula\Laravel\Authorization\Services\BoundaryService
     */
    private static function service(): BoundaryService
    {
        $service = BoundaryService::instance();

        self::assertInstanceOf(BoundaryService::class, $service);

        return $service;
    }

    /**
     * Create a boundary policy allowing `posts:read`, with the attributes.
     *
     * @param  string  $name
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function cap(string $name, array $attributes = []): Policy
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
