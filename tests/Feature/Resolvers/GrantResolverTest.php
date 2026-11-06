<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\GrantResolver;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for resolving what an identity's grants come to, the versions
 * each resolution pins, and the expiry it reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantResolver::class)]
final class GrantResolverTest extends TestCase
{
    /**
     * Start the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-01 12:00:00');
    }

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Roles resolve to their names in the order they were granted, pinning each
     * role, and expire with the nearest grant.
     *
     * @return void
     */
    public function testRolesResolveInGrantOrderAndPinEachRole(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $zeta   = Role::create(['name' => 'zeta']);
        $alpha  = Role::create(['name' => 'alpha']);
        $expiry = Carbon::parse('2026-07-01 12:10:00');

        $user->assignRole($zeta);
        $user->assignRole($alpha, $expiry);

        [$pins, $store] = self::pins();

        $resolution = GrantResolver::roles($user->roles(), $pins);

        self::assertSame(['zeta', 'alpha'], $resolution->value);
        self::assertSame(600, $resolution->expiresIn);
        self::assertTrue($resolution->stable);
        self::assertSame([$store->roleKey($zeta->id), $store->roleKey($alpha->id)], \array_keys($pins->tokens()));
    }

    /**
     * Without grants nothing resolves, and nothing expires.
     *
     * @return void
     */
    public function testNoGrantsResolveToNothing(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        self::assertSame([], GrantResolver::roles($user->roles(), new ResolutionPins)->value);
        self::assertNull(GrantResolver::roles($user->roles(), new ResolutionPins)->expiresIn);
        self::assertSame([], GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins)->value);
        self::assertSame([], GrantResolver::policies($user->policies(), new ResolutionPins)->value);

        self::assertSame(1, self::queriesFor(static fn () => GrantResolver::roles($user->roles(), new ResolutionPins)));
        self::assertSame(2, self::queriesFor(static fn () => GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins)));
        self::assertSame(1, self::queriesFor(static fn () => GrantResolver::policies($user->policies(), new ResolutionPins)));
    }

    /**
     * A permission granted directly and through a role is listed once, and the
     * names stay a list.
     *
     * @return void
     */
    public function testAPermissionHeldTwiceIsListedOnce(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'writer']);

        $role->givePermission(Permission::create(['name' => 'posts:read']));
        $role->givePermission(Permission::create(['name' => 'posts:write']));
        $user->givePermission('posts:read');
        $user->assignRole($role);

        $names = GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins)->value;

        self::assertSame([0, 1], \array_keys($names));
        self::assertEqualsCanonicalizing(['posts:read', 'posts:write'], $names);
    }

    /**
     * A role deleted while the resolution runs, after the grants were read, is
     * left out, and the roles after it are still listed.
     *
     * @return void
     */
    public function testARoleDeletedWhileResolvingIsLeftOut(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $first = Role::create(['name' => 'first']);

        $user->assignRole($first);
        $user->assignRole(Role::create(['name' => 'second']));

        $store = new VersionedStore(new Repository(self::onFirstPin(static fn () => DB::table('roles')->where('id', $first->id)->delete())), 'authz');

        self::assertSame(['second'], GrantResolver::roles($user->roles(), new ResolutionPins($store))->value);
    }

    /**
     * Permissions resolve to the direct grants and those held through the roles
     * and their ancestors, each once, pinning every role read, and expire with
     * the nearest grant of either kind.
     *
     * @return void
     */
    public function testPermissionsComeDirectlyAndThroughTheHierarchy(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $parent = Role::create(['name' => 'reader']);
        $role   = Role::create(['name' => 'writer', 'parent_id' => $parent->id]);

        $parent->givePermission(Permission::create(['name' => 'posts:read']));
        $role->givePermission(Permission::create(['name' => 'posts:write']));

        $user->givePermission('posts:read', Carbon::parse('2026-07-01 12:05:00'));
        $user->assignRole($role, Carbon::parse('2026-07-01 12:10:00'));

        [$pins, $store] = self::pins();

        $resolution = GrantResolver::permissions($user->permissions(), $user->roles(), $pins);

        self::assertEqualsCanonicalizing(['posts:read', 'posts:write'], $resolution->value);
        self::assertCount(2, $resolution->value);
        self::assertSame(300, $resolution->expiresIn);
        self::assertTrue($resolution->stable);
        self::assertEqualsCanonicalizing([$store->roleKey($role->id), $store->roleKey($parent->id)], \array_keys($pins->tokens()));
    }

    /**
     * A role moved under a parent the resolution had not read, between reading
     * the hierarchy and its permissions, still resolves to the moved role's
     * permissions afresh, expiring with them, but is marked unstable so it is
     * not stored.
     *
     * @return void
     */
    public function testAHierarchyThatMovesWhileResolvingIsUnstable(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $parent = Role::create(['name' => 'publisher']);
        $role   = Role::create(['name' => 'editor']);

        $parent->givePermission(Permission::create(['name' => 'posts:publish']), Carbon::parse('2026-07-01 12:01:00'));
        $user->assignRole($role);

        $store = new VersionedStore(new Repository(self::onFirstPin(static fn () => DB::table('roles')->where('id', $role->id)->update(['parent_id' => $parent->id]))), 'authz');

        $resolution = GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins($store));

        self::assertSame(['posts:publish'], $resolution->value);
        self::assertSame(60, $resolution->expiresIn);
        self::assertFalse($resolution->stable);
    }

    /**
     * A role's grant of a permission that expires sooner than any grant of the
     * identity's bounds the resolution, and one that has expired is left out.
     *
     * @return void
     */
    public function testARolesPermissionThatExpiresSoonerBoundsTheResolution(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'writer']);

        $role->givePermission(Permission::create(['name' => 'posts:write']), Carbon::parse('2026-07-01 12:02:00'));
        $role->givePermission(Permission::create(['name' => 'posts:lapsed']), Carbon::parse('2026-07-01 11:00:00'));
        $user->givePermission(Permission::create(['name' => 'posts:read']), Carbon::parse('2026-07-01 12:05:00'));
        $user->assignRole($role);

        $resolution = GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins);

        self::assertEqualsCanonicalizing(['posts:read', 'posts:write'], $resolution->value);
        self::assertSame(120, $resolution->expiresIn);
    }

    /**
     * Policies resolve in the order they were attached, pinning each, and
     * expire with the nearest attachment.
     *
     * @return void
     */
    public function testPoliciesResolveInAttachmentOrderAndPinEachPolicy(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $writers = Policy::create(['name' => 'writers', 'document' => ['version' => 1, 'statements' => []]]);
        $readers = Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);

        $user->attachPolicy($writers, Carbon::parse('2026-07-01 12:01:00'));
        $user->attachPolicy($readers);

        [$pins, $store] = self::pins();

        $resolution = GrantResolver::policies($user->policies(), $pins);

        self::assertSame(['writers', 'readers'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $resolution->value));
        self::assertSame(60, $resolution->expiresIn);
        self::assertSame([$store->policyKey($writers->id), $store->policyKey($readers->id)], \array_keys($pins->tokens()));
    }

    /**
     * A policy whose document cannot be read is written to the log channel and
     * its exception thrown, so it denies rather than being skipped.
     *
     * @return void
     */
    public function testAnUnreadablePolicyIsLoggedAndThrown(): void
    {
        $logger = new RecordingLogger;
        $this->app?->instance('log', $logger);

        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = Policy::create(['name' => 'broken', 'document' => ['version' => 1, 'statements' => []]]);

        $user->attachPolicy($policy);

        $unreadable = ['statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => []]]];

        DB::table('policies')->where('id', $policy->id)->update(['document' => \json_encode($unreadable)]);

        $reason = 'Invalid policy document \'broken\': Policy statement resources must be a non-empty list of non-empty strings.';

        try {
            GrantResolver::policies($user->policies(), new ResolutionPins);
            self::fail('An unreadable policy was not thrown.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertSame($reason, $exception->getMessage());
        }

        self::assertSame([[
            'level'   => 'warning',
            'message' => "Authorization: malformed policy '{$policy->id}' denies every check for its holder: {$reason}",
            'context' => ['policy_id' => $policy->id, 'policy_name' => 'broken', 'reason' => $reason],
        ]], $logger->records);
    }

    /**
     * Return an array store that runs the write the first time versions are
     * read, as a write committing while a resolution runs would.
     *
     * @param  \Closure(): mixed  $write
     * @return \Illuminate\Cache\ArrayStore
     */
    private static function onFirstPin(\Closure $write): ArrayStore
    {
        return new class ($write) extends ArrayStore {
            /**
             * @param  \Closure(): mixed|null  $onPin
             */
            public function __construct(

                /** The write to run; run once, then cleared. */
                private ?\Closure $onPin,
            ) {
                parent::__construct();
            }

            /**
             * Run the write the first time versions are read.
             *
             * @param  array<mixed>  $keys
             * @return array<string, mixed>
             */
            #[\Override]
            public function many(array $keys): array
            {
                if ($this->onPin !== null) {
                    ($this->onPin)();
                    $this->onPin = null;
                }

                return parent::many($keys);
            }
        };
    }

    /**
     * Count the queries the work runs.
     *
     * @param  \Closure(): mixed  $work
     * @return int
     */
    private static function queriesFor(\Closure $work): int
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $work();

        $count = \count(DB::getQueryLog());

        DB::disableQueryLog();

        return $count;
    }

    /**
     * Return pins over a fresh store, and the store.
     *
     * @return array{0: \SineMacula\Laravel\Authorization\Cache\ResolutionPins, 1: \SineMacula\Laravel\Authorization\Cache\VersionedStore}
     */
    private static function pins(): array
    {
        $store = new VersionedStore(new Repository(new ArrayStore), 'authz');

        return [new ResolutionPins($store), $store];
    }
}
