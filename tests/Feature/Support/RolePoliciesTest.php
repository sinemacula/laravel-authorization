<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\GrantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\InheritedPolicies;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RolePolicies;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the policies an identity gets through its roles: within
 * both grants' scopes, down the role hierarchy, with the expiry and versions
 * the resolution reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RolePolicies::class)]
final class RolePoliciesTest extends TestCase
{
    use ActsAsTenant;

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
     * A policy attached to a role applies to whoever holds the role, alongside
     * the holder's own, and to no one else.
     *
     * @return void
     */
    public function testARolesPolicyAppliesToItsHolders(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $other  = StubIdentity::create(['id' => 'user-2']);
        $editor = Role::create(['name' => 'editor']);

        $editor->attachPolicy(self::policy('editors'));
        $user->attachPolicy(self::policy('own'));
        $user->assignRole($editor);

        self::assertSame(['editors', 'own'], self::policyNames($user));
        self::assertSame([], self::policyNames($other));
        self::assertSame(['editors'], self::names($editor->getPolicies()));
    }

    /**
     * A role's policy applies only in the tenants where the role is held, and
     * where its attachment holds: both grants must reach the tenant.
     *
     * @return void
     */
    public function testARolesPolicyAppliesOnlyWhereBothGrantsHoldInTheTenant(): void
    {
        [$tenantA, $tenantB] = \array_map(self::createTenant(...), ['tenant-a', 'tenant-b']);

        $user    = StubIdentity::create(['id' => 'user-1']);
        $local   = Role::create(['name' => 'local']);
        $global  = Role::create(['name' => 'global']);
        $minimal = self::policy('in-a');

        $local->attachPolicy(self::policy('everywhere'));
        $global->attachPolicy($minimal, null, $tenantA);
        $user->assignRole($local, null, $tenantA);
        $user->assignRole($global);

        self::assertSame(['everywhere', 'in-a'], self::policyNames($user, $tenantA));
        self::assertSame([], self::policyNames($user, $tenantB));
        self::assertSame([], self::policyNames($user));
    }

    /**
     * A role's policy applies only on the applications both grants hold on.
     *
     * @return void
     */
    public function testARolesPolicyAppliesOnlyWhereBothGrantsHoldOnTheApplication(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $admin  = Role::create(['name' => 'admin']);
        $mobile = Role::create(['name' => 'mobile']);

        $admin->attachPolicy(self::policy('admin-role'));
        $mobile->attachPolicy(self::policy('mobile-attachment'), application: 'mobile');
        $user->assignRole($admin, application: 'admin');
        $user->assignRole($mobile);

        self::assertSame(['admin-role'], self::policyNames($user, null, 'admin'));
        self::assertSame(['mobile-attachment'], self::policyNames($user, null, 'mobile'));
        self::assertSame([], self::policyNames($user));
    }

    /**
     * A role's policy stops applying when the role's grant or the policy's
     * attachment expires, and the resolution lasts no longer than the nearest
     * of them.
     *
     * @return void
     */
    public function testARolesPolicyLapsesWithEitherGrant(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $role    = Role::create(['name' => 'editor']);
        $lapsing = Role::create(['name' => 'lapsing']);

        $role->attachPolicy(self::policy('soon'), Carbon::parse('2026-07-01 12:05:00'));
        $lapsing->attachPolicy(self::policy('lapsing'));
        $user->assignRole($role, Carbon::parse('2026-07-01 12:10:00'));
        $user->assignRole($lapsing, Carbon::parse('2026-07-01 12:02:00'));

        $resolution = GrantResolver::policies($user->policies(), new ResolutionPins, $user->roles());

        self::assertSame(['soon', 'lapsing'], \array_values(\array_intersect(['soon', 'lapsing'], self::names($resolution->value))));
        self::assertSame(120, $resolution->expiresIn);

        Carbon::setTestNow('2026-07-01 12:03:00');

        self::assertSame(['soon'], self::policyNames($user));

        Carbon::setTestNow('2026-07-01 12:06:00');

        self::assertSame([], self::policyNames($user));
    }

    /**
     * The resolution lasts no longer than a role's attachment of a policy when
     * that attachment expires first, before the role's grant and the holder's
     * own attachment.
     *
     * @return void
     */
    public function testARolesAttachmentBoundsTheResolution(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'editor']);

        $role->attachPolicy(self::policy('soon'), Carbon::parse('2026-07-01 12:02:00'));
        $user->assignRole($role, Carbon::parse('2026-07-01 12:10:00'));
        $user->attachPolicy(self::policy('own'), Carbon::parse('2026-07-01 12:20:00'));

        self::assertSame(120, GrantResolver::policies($user->policies(), new ResolutionPins, $user->roles())->expiresIn);
    }

    /**
     * The probe reads at most one attachment, however many roles hold a policy
     * in the scope.
     *
     * @return void
     */
    public function testTheProbeReadsAtMostOneAttachment(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        foreach (['first', 'second', 'third'] as $name) {
            Role::create(['name' => $name])->attachPolicy(self::policy($name));
        }

        self::assertCount(1, RolePolicies::probe($user->roles(), ['policy_id', 'authorizable_type', 'expires_at'])->get());
    }

    /**
     * With no role held, nothing is read and nothing applies.
     *
     * @return void
     */
    public function testNoHeldRoleReadsNothing(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        Role::create(['name' => 'editor'])->attachPolicy(self::policy('editors'));

        $inherited = null;

        self::assertSame(0, self::queriesFor(static function () use ($user, &$inherited): void {
            $inherited = RolePolicies::heldThrough(new EloquentCollection, $user->roles(), new ResolutionPins);
        }));
        self::assertEquals(new InheritedPolicies, $inherited);
    }

    /**
     * An attachment of an inline policy to a role other than the one it belongs
     * to, written past the write paths, never applies to the role's holders,
     * nor makes the resolution read the roles.
     *
     * @return void
     */
    public function testAnotherRolesInlinePolicyNeverApplies(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $owner  = Role::create(['name' => 'owner']);
        $holder = Role::create(['name' => 'holder']);
        $inline = $owner->createInlinePolicy('owners', ['version' => 1, 'statements' => []]);

        DB::table('authorizable_policies')->insert(['policy_id' => $inline->id, 'authorizable_type' => $holder->getMorphClass(), 'authorizable_id' => $holder->id]);
        $user->assignRole($holder);

        self::assertSame(1, self::queriesFor(static fn () => GrantResolver::policies($user->policies(), new ResolutionPins, $user->roles())));
        self::assertSame([], self::policyNames($user));

        $user->assignRole($owner);
        $owner->attachPolicy($inline);

        self::assertSame(['owners'], self::policyNames($user));
    }

    /**
     * A role's grant, or its attachment of a policy, limited to a tenant does
     * not reach the tenants below it; one that reaches the subtree does.
     *
     * @return void
     */
    public function testARolesPolicyReachesTheSubtreeOnlyWhereBothGrantsDo(): void
    {
        [$org, $account] = \array_map(self::createTenant(...), ['org', 'account']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($account), Reference::of($org)));

        $user     = StubIdentity::create(['id' => 'user-1']);
        $orgOnly  = Role::create(['name' => 'org-only']);
        $reaching = Role::create(['name' => 'reaching']);

        $orgOnly->attachPolicy(self::policy('held-in-org-only'));
        $reaching->attachPolicy(self::policy('attached-in-org-only'), null, $org, false);
        $reaching->attachPolicy(self::policy('attached-below'), null, $org);
        $user->assignRole($orgOnly, null, $org, false);
        $user->assignRole($reaching, null, $org);

        self::assertSame(['attached-below', 'attached-in-org-only', 'held-in-org-only'], self::policyNames($user, $org));
        self::assertSame(['attached-below'], self::policyNames($user, $account));
    }

    /**
     * A role's policies are inherited down the hierarchy, as its permissions
     * are: the holder of a role gets its ancestors' policies, never a sibling's
     * or a descendant's.
     *
     * @return void
     */
    public function testARolesPoliciesAreInheritedDownTheHierarchy(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $root    = Role::create(['name' => 'root']);
        $middle  = Role::create(['name' => 'middle', 'parent_id' => $root->id]);
        $leaf    = Role::create(['name' => 'leaf', 'parent_id' => $middle->id]);
        $sibling = Role::create(['name' => 'sibling', 'parent_id' => $root->id]);
        $child   = Role::create(['name' => 'child', 'parent_id' => $leaf->id]);

        foreach ([$root, $middle, $leaf, $sibling, $child] as $role) {
            $role->attachPolicy(self::policy("{$role->name}-policy"));
        }

        $user->assignRole($leaf);

        self::assertSame(['leaf-policy', 'middle-policy', 'root-policy'], self::policyNames($user));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame(['leaf-policy'], self::policyNames($user));
    }

    /**
     * A policy held directly and through two roles is listed once.
     *
     * @return void
     */
    public function testAPolicyHeldSeveralWaysIsListedOnce(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::policy('shared');
        $parent = Role::create(['name' => 'parent']);
        $child  = Role::create(['name' => 'child', 'parent_id' => $parent->id]);

        $parent->attachPolicy($policy);
        $child->attachPolicy($policy);
        $user->attachPolicy($policy);
        $user->assignRole($child);

        self::assertSame(['shared'], self::policyNames($user));
    }

    /**
     * A deny in a role's policy refuses what the holder's permission would
     * allow, as a deny in its own policy does, and is reported as an explicit
     * deny.
     *
     * @return void
     */
    public function testADenyInARolesPolicyRefusesThePermission(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $parent = Role::create(['name' => 'staff']);
        $role   = Role::create(['name' => 'editor', 'parent_id' => $parent->id]);

        $role->givePermission(Permission::create(['name' => 'posts:delete']));
        $role->givePermission(Permission::create(['name' => 'posts:edit']));
        $parent->attachPolicy(Policy::create(['name' => 'no-deletes', 'document' => [
            'version'    => 1,
            'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]],
        ]]));
        $user->assignRole($role);

        $manager = $this->app?->make(AuthorizationManager::class);

        self::assertNotNull($manager);
        self::assertTrue($manager->for($user)->can('posts:edit'));
        self::assertFalse($manager->for($user)->can('posts:delete'));
        self::assertSame(DecisionReason::EXPLICIT_DENY, $manager->for($user)->check('posts:delete')->reason);
    }

    /**
     * Role policies, the holder's own (inline among them) and the bound policy
     * store's are evaluated together, whatever order each source lists them in:
     * the evaluator orders them by name, then stored key, then document, so the
     * same policies give the same trace however they arrive.
     *
     * @return void
     */
    public function testEverySourceCombinesInOneDeterministicOrder(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $role   = Role::create(['name' => 'editor']);
        $stored = EvaluationPolicy::fromArray(['name' => 'b-stored', 'version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]);

        $role->attachPolicy(self::allowing('c-role'));
        $user->attachPolicy(self::allowing('d-own'));
        $user->attachPolicy($user->createInlinePolicy('a-inline', ['version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]));
        $user->assignRole($role);

        $this->app?->instance(PolicyStore::class, new class ($stored) implements PolicyStore {
            /**
             * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
             */
            public function __construct(

                /** The policy the store returns. */
                private readonly EvaluationPolicy $policy,
            ) {}

            /**
             * Return the stored policy for every principal.
             *
             * @param  object  $principal
             * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
             */
            #[\Override]
            public function policiesFor(object $principal): array
            {
                return [$this->policy];
            }
        });

        $policies = (new DefaultPolicyResolver($this->app?->make(PolicyStore::class)))->policiesFor($user);

        self::assertEqualsCanonicalizing(['a-inline', 'b-stored', 'c-role', 'd-own'], self::names($policies));

        $forward  = (new PolicyEvaluator)->evaluate($policies, 'posts:read');
        $backward = (new PolicyEvaluator)->evaluate(\array_reverse($policies), 'posts:read');

        self::assertSame(['a-inline', 'b-stored', 'c-role', 'd-own'], \array_map(static fn (TraceEntry $entry): ?string => $entry->statement?->policy, $forward->trace));
        self::assertEquals($forward->trace, $backward->trace);
    }

    /**
     * The resolution pins the version every role's policy attachments share
     * before it reads, then every role it reaches and every policy it reads.
     *
     * @return void
     */
    public function testTheResolutionPinsTheSharedVersionTheRolesAndThePolicies(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $parent = Role::create(['name' => 'parent']);
        $role   = Role::create(['name' => 'child', 'parent_id' => $parent->id]);
        $policy = self::policy('parents');

        $parent->attachPolicy($policy);
        $user->assignRole($role);

        $store = new VersionedStore(new Repository(new ArrayStore), 'authz');
        $pins  = new ResolutionPins($store);

        GrantResolver::policies($user->policies(), $pins, $user->roles());

        $keys = \array_keys($pins->tokens());

        self::assertSame($store->rolePoliciesKey(), $keys[0]);
        self::assertEqualsCanonicalizing([$store->rolePoliciesKey(), $store->roleKey($role->id), $store->roleKey($parent->id), $store->policyKey($policy->id)], $keys);
    }

    /**
     * Without any role holding a policy in the scope, the roles are not read:
     * the identity's own attachments and that answer take one query.
     *
     * @return void
     */
    public function testWithoutARolesPolicyInScopeTheRolesAreNotRead(): void
    {
        [$tenantA] = \array_map(self::createTenant(...), ['tenant-a']);

        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'editor']);

        $role->attachPolicy(self::policy('in-a'), null, $tenantA);
        $user->assignRole($role);

        $resolve = static fn () => GrantResolver::policies($user->policies(), new ResolutionPins, $user->roles());

        self::assertSame(1, self::queriesFor($resolve));
        self::assertSame(6, self::queriesFor(static fn () => TenantScope::within($tenantA, null, $resolve)));
    }

    /**
     * A role moved under a parent while the resolution runs still gets the
     * parent's policies, read afresh, but the resolution is marked unstable so
     * it is not stored.
     *
     * @return void
     */
    public function testAHierarchyThatMovesWhileResolvingIsUnstable(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $parent = Role::create(['name' => 'publisher']);
        $role   = Role::create(['name' => 'editor']);

        $parent->attachPolicy(self::policy('publishers'));
        $user->assignRole($role);

        $moved = false;
        $store = new VersionedStore(new Repository(self::onPin(static function (array $keys) use (&$moved, $role, $parent): void {
            // Move the role once its reach has been read, as the roles it
            // reached are pinned.
            if ($moved || !\in_array('authz:version:role:' . $role->id, $keys, true)) {
                return;
            }

            $moved = true;

            DB::table('roles')->where('id', $role->id)->update(['parent_id' => $parent->id]);
        })), 'authz');

        $resolution = GrantResolver::policies($user->policies(), new ResolutionPins($store), $user->roles());

        self::assertSame(['publishers'], self::names($resolution->value));
        self::assertFalse($resolution->stable);
    }

    /**
     * A holder whose roles are all hidden by the tenant scope, or who holds
     * none, gets no role's policy, though a role somewhere holds one.
     *
     * @return void
     */
    public function testAHolderWithoutRolesGetsNoRolesPolicy(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        Role::create(['name' => 'editor'])->attachPolicy(self::policy('editors'));

        $resolution = GrantResolver::policies($user->policies(), new ResolutionPins, $user->roles());

        self::assertSame([], $resolution->value);
        self::assertNull($resolution->expiresIn);
        self::assertTrue($resolution->stable);
    }

    /**
     * A holder whose roles hold no policy in the scope gets none, though
     * another role does, and the grants of its roles do not bound the
     * resolution, since no policy came through them.
     *
     * @return void
     */
    public function testRolesHoldingNoPolicyDoNotBoundTheResolution(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        Role::create(['name' => 'author'])->attachPolicy(self::policy('authors'));
        $user->assignRole(Role::create(['name' => 'editor']), Carbon::parse('2026-07-01 12:05:00'));

        $resolution = GrantResolver::policies($user->policies(), new ResolutionPins, $user->roles());

        self::assertSame([], $resolution->value);
        self::assertNull($resolution->expiresIn);
        self::assertTrue($resolution->stable);
    }

    /**
     * Create a policy that allows nothing.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['version' => 1, 'statements' => []]]);
    }

    /**
     * Create a policy that allows reading posts.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function allowing(string $name): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);
    }

    /**
     * Return the names of the identity's policies in the tenant and on the
     * application, read afresh, in name order.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @param  string|null  $application
     * @return list<string>
     */
    private function policyNames(StubIdentity $user, ?StubTenant $tenant = null, ?string $application = null): array
    {
        $this->app?->forgetInstance(ResolutionCache::class);

        $fresh = StubIdentity::query()->whereKey($user->getKey())->firstOrFail();

        /** @var list<string> $names */
        $names = TenantScope::within($tenant, $application, static fn (): array => self::names($fresh->getPolicies()));

        \sort($names);

        return $names;
    }

    /**
     * Return the names of the policies.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<string>
     */
    private static function names(array $policies): array
    {
        return \array_values(\array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $policies));
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
     * Return an array store that runs the callback, with the keys read, each
     * time versions are read, as writes committing while a resolution runs
     * would.
     *
     * @param  \Closure(array<mixed>): void  $onPin
     * @return \Illuminate\Cache\ArrayStore
     */
    private static function onPin(\Closure $onPin): ArrayStore
    {
        return new class ($onPin) extends ArrayStore {
            /**
             * @param  \Closure(array<mixed>): void  $onPin
             */
            public function __construct(

                /** The callback run on every pin. */
                private readonly \Closure $onPin,
            ) {
                parent::__construct();
            }

            /**
             * Run the callback, then read the versions.
             *
             * @param  array<mixed>  $keys
             * @return array<string, mixed>
             */
            #[\Override]
            public function many(array $keys): array
            {
                ($this->onPin)($keys);

                return parent::many($keys);
            }
        };
    }
}
