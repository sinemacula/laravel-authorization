<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Administration\RoleAuthority;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\BulkChecks\FailingTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `RoleAuthority`: the whole active authority a role hands
 * out, read in a fixed number of queries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleAuthority::class)]
final class RoleAuthorityTest extends TestCase
{
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
     * A role's authority is what it and its ancestors carry live: their
     * permissions and their policies, each once, whatever tenant owns them; a
     * grant or an attachment that has expired hands out nothing; with the
     * hierarchy disabled, the role's own alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleHandsOutWhatItsChainCarriesLive(): void
    {
        $root   = Role::query()->create(['name' => 'root']);
        $parent = Role::query()->create(['name' => 'parent', 'parent_id' => $root->id]);
        $child  = Role::query()->withoutGlobalScopes()->create(['name' => 'child', 'parent_id' => $parent->id, 'tenant_type' => 'tenant', 'tenant_id' => 'a']);
        $read   = Policy::create(['name' => 'reader', 'document' => ['statements' => []]]);
        $stale  = Policy::create(['name' => 'stale', 'document' => ['statements' => []]]);

        self::roles()->grantPermission($root, self::permission('posts:delete'));
        self::roles()->grantPermission($parent, self::permission('posts:edit'));
        self::roles()->grantPermission($child, self::permission('posts:read'));
        self::roles()->grantPermission($child, self::permission('posts:edit'));
        self::roles()->grantPermission($child, self::permission('posts:archive'), Carbon::now()->addDay());
        self::grants()->attachPolicy($parent, $read);
        self::grants()->attachPolicy($root, $read);
        self::grants()->attachPolicy($child, $stale, Carbon::now()->addDay());

        Carbon::setTestNow(Carbon::now()->addDays(2));

        $authority = RoleAuthority::of([$child->id]);

        self::assertNotNull($authority);
        self::assertEqualsCanonicalizing(['posts:delete', 'posts:edit', 'posts:read'], self::names($authority->permissions));
        self::assertSame(['reader'], self::names($authority->policies));
        self::assertEqualsCanonicalizing([$child->id, $parent->id, $root->id], RoleAuthority::chainsOf([$child->id, $parent->id]));

        config(['authorization.hierarchy.enabled' => false]);

        $own = RoleAuthority::of([$child->id]);

        self::assertEqualsCanonicalizing(['posts:read', 'posts:edit'], self::names($own->permissions ?? []));
        self::assertSame([], $own?->policies);
    }

    /**
     * A chain that cannot be read whole hands out nothing that can be proved: a
     * role that does not exist, or a walk that returns to a role it has passed,
     * reads as none.
     *
     * @return void
     */
    public function testAChainThatCannotBeReadWholeReadsAsNone(): void
    {
        self::assertNull(RoleAuthority::of(['01a1b0c0-0000-7000-8000-00000000dead']));
        self::assertNull(RoleAuthority::chainOf('a', ['a' => 'b', 'b' => 'a']));
        self::assertNull(RoleAuthority::chainOf('a', ['a' => 'b']));
        self::assertSame(['a', 'b', 'c'], RoleAuthority::chainOf('a', ['a' => 'b', 'b' => 'c', 'c' => null]));
        self::assertSame([], RoleAuthority::chainsOf([]));
        self::assertEquals(RoleAuthority::of([]), RoleAuthority::of([]));
        self::assertSame([], RoleAuthority::of([])?->permissions);
    }

    /**
     * The authority is read in the same number of queries however deep the
     * chain runs and however much it carries, and a chain with no policy
     * attached reads none of them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAuthorityIsReadInAFixedNumberOfQueries(): void
    {
        $shallow = self::chain('shallow', 1);
        $deep    = self::chain('deep', 6);

        self::assertSame(self::queriesOf($shallow), self::queriesOf($deep));
        self::assertSame(self::queriesOf($shallow) - 1, self::queriesOf(Role::query()->create(['name' => 'bare'])->id));
    }

    /**
     * The authority is handed out by the permission route for each permission
     * and the policy route for each policy, the first refusal winning; one that
     * carries nothing is handed out freely.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFirstRouteThatRefusesRefusesTheAuthority(): void
    {
        $role   = Role::query()->create(['name' => 'editor']);
        $user   = StubIdentity::query()->create(['id' => 'user']);
        $actor  = StubIdentity::query()->create(['id' => 'admin']);
        $denied = static fn (): Decision => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        $checks = new FurtherChecks(new Subject($actor, $actor), $denied, static fn (): null => null);
        $grant  = OperationResource::grant(PackagePermissions::ROLE_GRANT, $user, $role, GrantScope::platform());

        /** @var \SineMacula\Laravel\Authorization\Administration\OperationChange $change */
        $change = $grant->change;

        self::assertNull(self::authorityOf($role->id)->refusal($grant, $change, $checks));

        $scoped = ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['posts:1']];

        self::grants()->attachPolicy($role, Policy::create(['name' => 'scoped', 'document' => ['statements' => [$scoped]]]));

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::authorityOf($role->id)->refusal($grant, $change, $checks));

        self::roles()->grantPermission($role, self::permission('posts:edit'));

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, self::authorityOf($role->id)->refusal($grant, $change, $checks));
    }

    /**
     * A role also hands out the allows of every policy attached to a resource
     * in the reach that name it, or an ancestor, as a principal: those allows
     * alone, never a deny or an allow naming another, and only from a policy
     * attached in a tenant of the reach or platform-wide; with the hierarchy
     * disabled, the role's own alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleHandsOutTheResourcePolicyAllowsNamingItsChain(): void
    {
        $root   = Role::query()->create(['name' => 'root']);
        $child  = Role::query()->create(['name' => 'child', 'parent_id' => $root->id]);
        $other  = Role::query()->create(['name' => 'other']);
        $naming = self::resourcePolicy('naming', [
            ['effect' => 'allow', 'actions' => ['posts:delete'], 'principals' => ['role:' . $root->id]],
            ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['role:' . $other->id]],
            ['effect' => 'deny', 'actions' => ['posts:edit']],
        ]);

        self::resourcePolicy('elsewhere', [['effect' => 'allow', 'actions' => ['posts:archive'], 'principals' => ['role:' . $child->id]]], new Reference('tenant', 'other'));
        self::resourcePolicy('unnamed', [['effect' => 'allow', 'actions' => ['posts:publish'], 'principals' => ['user:1']]]);

        $inTenant = self::authorityOf($child->id, new GrantScope(new Reference('tenant', 'a')));
        $platform = self::authorityOf($child->id);

        self::assertSame([['naming', [['posts:delete']]]], self::selected($inTenant));
        self::assertEqualsCanonicalizing([['naming', [['posts:delete']]], ['elsewhere', [['posts:archive']]]], self::selected($platform));
        self::assertSame($naming->getKey(), $inTenant->selecting[0][0]->getKey());

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame([['elsewhere', [['posts:archive']]]], self::selected(self::authorityOf($child->id)));
        self::assertSame([], self::authorityOf($child->id, new GrantScope(new Reference('tenant', 'a')))->selecting);
    }

    /**
     * The resource policies are never guessed: a reach whose tenants cannot be
     * read, more of them in the reach than the impact limit allows, of which
     * one more than it is read, or one whose document cannot be read, reads as
     * no authority at all; no roles read none of them, and nothing at all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testResourcePoliciesThatCannotBeReadWholeReadAsNone(): void
    {
        $role = Role::query()->create(['name' => 'editor']);

        self::resourcePolicy('first', [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]]);

        $broken = self::resourcePolicy('second', [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:2']]]);
        $tenant = new GrantScope(new Reference('tenant', 'a'));

        config(['authorization.administration.max_impact' => 2]);

        self::assertNotNull(RoleAuthority::of([$role->id]));

        config(['authorization.administration.max_impact' => 1]);

        DB::flushQueryLog();
        DB::enableQueryLog();

        self::assertNull(RoleAuthority::of([$role->id]));

        $reads = \array_filter(\array_column(DB::getQueryLog(), 'query'), static fn (string $query): bool => \str_contains($query, 'resource_policies'));

        DB::disableQueryLog();

        self::assertCount(1, $reads);
        self::assertStringEndsWith('limit 2', \current($reads));

        config(['authorization.administration.max_impact' => 2]);

        $this->app?->instance(TenantTree::class, new FailingTenantTree(failing: ['a']));

        self::assertNull(RoleAuthority::of([$role->id], $tenant));

        DB::table('policies')->where('id', $broken->getKey())->update(['document' => '{"statements": 5}']);

        self::assertNull(RoleAuthority::of([$role->id]));

        DB::flushQueryLog();
        DB::enableQueryLog();

        self::assertSame([], RoleAuthority::of([])?->selecting);
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * An allow a resource policy hands a role's holders is weighed by the
     * policy route, its principals no bar to containment: one naming an action
     * the actor cannot hand out is refused as not grantable, and one with a
     * condition, which cannot be contained, as unprovable, unless a permission
     * the role carries is refused first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourcePolicysAllowsAreWeighedByThePolicyRoute(): void
    {
        $role   = Role::query()->create(['name' => 'editor']);
        $user   = StubIdentity::query()->create(['id' => 'user']);
        $actor  = StubIdentity::query()->create(['id' => 'admin']);
        $denied = static fn (): Decision => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        $checks = new FurtherChecks(new Subject($actor, $actor), $denied, static fn (): null => null);
        $grant  = OperationResource::grant(PackagePermissions::ROLE_GRANT, $user, $role, GrantScope::platform());

        /** @var \SineMacula\Laravel\Authorization\Administration\OperationChange $change */
        $change = $grant->change;

        self::resourcePolicy('deleting', [['effect' => 'allow', 'actions' => ['posts:delete'], 'principals' => ['role:' . $role->id]]]);

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, self::authorityOf($role->id)->refusal($grant, $change, $checks));

        DB::table('resource_policies')->delete();

        self::resourcePolicy('conditional', [[
            'effect'     => 'allow',
            'actions'    => ['posts:delete'],
            'principals' => ['role:' . $role->id],
            'conditions' => ['eq' => ['resource.owner' => 'me']],
        ]]);

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::authorityOf($role->id)->refusal($grant, $change, $checks));

        self::roles()->grantPermission($role, self::permission('posts:edit'));

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, self::authorityOf($role->id)->refusal($grant, $change, $checks));
    }

    /**
     * Return the authority of the role with the key, once it is known to be
     * read, across the reach, every tenant for none.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope|null  $reach
     * @return \SineMacula\Laravel\Authorization\Administration\RoleAuthority
     */
    private static function authorityOf(string $key, ?GrantScope $reach = null): RoleAuthority
    {
        $authority = RoleAuthority::of([$key], $reach);

        self::assertNotNull($authority);

        return $authority;
    }

    /**
     * Return the key of the lowest of a chain of the depth, each role carrying
     * a permission and a policy.
     *
     * @param  string  $name
     * @param  int  $depth
     * @return string
     *
     * @throws \Throwable
     */
    private static function chain(string $name, int $depth): string
    {
        $parent = null;

        for ($level = 0; $level < $depth; $level++) {
            $parent = Role::query()->create(['name' => "{$name}-{$level}", 'parent_id' => $parent?->id]);

            self::roles()->grantPermission($parent, self::permission("{$name}:{$level}"));
            self::grants()->attachPolicy($parent, Policy::create(['name' => "{$name}-{$level}", 'document' => ['statements' => []]]));
        }

        return (string) $parent?->id;
    }

    /**
     * Count the queries reading the authority of the role with the key takes.
     *
     * @param  string  $key
     * @return int
     */
    private static function queriesOf(string $key): int
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        RoleAuthority::of([$key]);

        $count = \count(DB::getQueryLog());

        DB::disableQueryLog();

        return $count;
    }

    /**
     * Return the names of the records.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Models\Policy>  $records
     * @return list<string>
     */
    private static function names(array $records): array
    {
        return \array_map(static fn (Permission|Policy $record): string => $record->name, $records);
    }

    /**
     * Create a policy of the statements, attached to every post, in the tenant
     * given or platform-wide.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    private static function resourcePolicy(string $name, array $statements, ?Reference $tenant = null): Policy
    {
        $policy = Policy::create(['name' => $name, 'document' => ['statements' => $statements]]);

        ResourcePolicyService::instance()?->attach($policy, 'posts', $tenant);

        return $policy;
    }

    /**
     * Return the name of each resource policy the authority hands out, with the
     * actions of each allow it hands out.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\RoleAuthority  $authority
     * @return list<array{string, array<array-key, array<int, string>|null>}>
     */
    private static function selected(RoleAuthority $authority): array
    {
        $actions = static fn (Statement $allow): ?array => $allow->actions;

        return \array_map(static fn (array $selected): array => [$selected[0]->name, \array_map($actions, $selected[1])], $authority->selecting);
    }

    /**
     * Return the platform permission of the name, created on first use.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function permission(string $name): Permission
    {
        return Permission::query()->firstOrCreate(['name' => $name]);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        return app(GrantService::class);
    }

    /**
     * Return the role service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleService
     */
    private static function roles(): RoleService
    {
        return app(RoleService::class);
    }
}
