<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;
use SineMacula\Laravel\Authorization\Query\ResourceShape;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Query\ScopeClass;
use SineMacula\Laravel\Authorization\Query\ScopeClasses;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\CountingTenantTree;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\TestCase;

/**
 * Feature tests for how a model's rows are split into the classes `check()`
 * decides alike: the request's, the active tenant's subtree cut at each anchor,
 * and the rows a platform-wide grant admits from outside; and, end to end, that
 * each kept row is one `check()` allows across those transitions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ScopeClasses::class)]
final class ScopeClassesTest extends TestCase
{
    use ScopesQueries;

    /** @var list<string> The organisation, its accounts, a sub-account, and a sibling organisation with an account. */
    private const array TENANTS = ['o1', 'a1', 'a2', 's1', 'o2', 'b1'];

    /**
     * A tenantless model has one class, every row; with no tenant active and no
     * platform-wide grant, a tenant-bearing model has the rows of no tenant
     * alone; with one active under the flat tree, its rows too.
     *
     * @return void
     */
    public function testTheRequestsClassesUnderTheFlatTree(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        self::assertSame([[QueryAuthorizer::EVERY_ROW, null, false, false]], self::described(self::classes($this->resolveRequest($user), new ScopedPost)));
        self::assertCount(1, self::classes($this->resolveRequest($user), new TenantScopedPost));

        $active = self::classes($this->resolveRequest($user, new Reference(self::tenantType(), 'o1')), new TenantScopedPost);

        self::assertCount(2, $active);
        self::assertSame(['o1', false, false], [$active[1]->tenant?->id, $active[1]->isBelow, $active[1]->isAdmitted]);
    }

    /**
     * Under a tree with subtrees, each anchor within the active tenant's
     * subtree gives its own rows and those strictly below it; a platform-wide
     * grant adds the rows outside, by anchor, and those on no anchor's chain.
     *
     * @return void
     */
    public function testATreeCutsTheSubtreeAtEachAnchor(): void
    {
        [$user, $tenants] = $this->tree();

        $user->givePermission(Permission::create(['name' => 'posts:view']), null, $tenants['a1'], false);

        $classes = self::classes($this->resolveRequest($user, $tenants['o1']), new TenantScopedPost);

        $cut = \array_map(static fn (ScopeClass $class): array => [$class->tenant?->id, $class->isBelow], \array_slice($classes, 1));

        self::assertSame([['o1', false], ['o1', true], ['a1', false], ['a1', true]], $cut);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        $editing  = self::classes($this->resolveRequest($user, $tenants['o1']), new TenantScopedPost, 'posts:edit');
        $admitted = \array_filter($editing, static fn (ScopeClass $class): bool => $class->isAdmitted);

        self::assertCount(1, $admitted);
        self::assertNull(\array_values($admitted)[0]->tenant);
    }

    /**
     * More anchors or more classes than allowed are refused, naming the limit,
     * a limit written as the environment gives a whole number included.
     *
     * @return void
     */
    public function testMoreScopesThanAllowedAreRefused(): void
    {
        [$user, $tenants] = $this->tree();
        $config           = $this->app?->make(ConfigRepository::class);

        foreach (['a1', 'a2', 's1'] as $id) {
            $user->givePermission(Permission::firstOrCreate(['name' => 'posts:view']), null, $tenants[$id]);
        }

        $manager = $this->resolveRequest($user, $tenants['o1']);

        $config?->set('authorization.query_scoping.max_scopes', '4');

        self::assertSame('authorization.query_scoping.max_scopes', self::refusal($manager)->refusals[0]->key);

        $config?->set('authorization.query_scoping.max_scopes', 16);
        $config?->set('authorization.query_scoping.max_anchors', 2);

        $refusal = self::refusal($manager);

        self::assertSame([RefusalReason::TOO_MANY_SCOPES], $refusal->reasons());
        self::assertSame('authorization.query_scoping.max_anchors', $refusal->refusals[0]->key);
    }

    /**
     * Once a class is cut below an anchor or admitted from outside, the tenant
     * columns of every authorization table must compare bytes; with only the
     * active tenant's rows they need not.
     *
     * @return void
     */
    public function testAnInexactAuthorizationTableIsRefusedWhenTheClassesNeedIt(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        $this->app?->make(ConfigRepository::class)->set('authorization.tables.resource_policies', 'scoped_folded_resource_policies');

        self::assertCount(2, self::classes($this->resolveRequest($user, new Reference(self::tenantType(), 'o1')), new TenantScopedPost));

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        $refusal = self::refusal($this->resolveRequest($user, new Reference(self::tenantType(), 'o1')));

        self::assertSame([RefusalReason::COLUMN_COLLATION], $refusal->reasons());
        self::assertSame('scoped_folded_resource_policies.tenant_type', $refusal->refusals[0]->key);
    }

    /**
     * A grant at the organisation reaching its subtree, one at an account alone
     * and one at a sub-account each allow exactly the rows `check()` allows,
     * from the organisation, an account and the sibling organisation.
     *
     * @return void
     */
    public function testGrantsAcrossTheSubtreeAgreeWithCheck(): void
    {
        [$user, $tenants] = $this->tree();

        $user->givePermission(Permission::create(['name' => 'posts:view']), null, $tenants['o1']);
        $user->givePermission(Permission::create(['name' => 'posts:edit']), null, $tenants['a1'], false);
        $user->givePermission(Permission::create(['name' => 'posts:delete']), null, $tenants['s1']);

        foreach (['o1', 'a1', 'o2'] as $active) {
            $manager = $this->resolveRequest($user, $tenants[$active]);

            foreach (['posts:view', 'posts:edit', 'posts:delete'] as $action) {
                self::assertAgrees($manager, $action, "{$action} in {$active}");
            }
        }
    }

    /**
     * A platform-wide grant admits the rows of every tenant, a tenant's
     * guardrail still capping its subtree's, the sibling organisation's
     * included; a platform-wide grant for another application admits none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformWideGrantAdmitsEveryTenantUnderItsGuardrails(): void
    {
        [$user, $tenants] = $this->tree();
        $admin            = StubIdentity::create(['id' => 'admin']);

        $admin->givePermission(Permission::create(['name' => PackagePermissions::GUARDRAIL_MANAGE]));
        $user->givePermission(Permission::create(['name' => 'posts:view']));
        $user->givePermission(Permission::create(['name' => 'posts:edit']), null, null, true, 'other');

        $guardrail = self::storedPolicy('only-view', [['effect' => 'allow', 'actions' => ['posts:edit']]]);

        app(GuardrailService::class)->set($guardrail, $tenants['o2'], ActingContext::for($admin));

        foreach ([null, 'a1'] as $active) {
            $manager = $this->resolveRequest($user, $active === null ? null : $tenants[$active]);

            self::assertAgrees($manager, 'posts:view', 'view in ' . ($active ?? 'the platform'));
            self::assertAgrees($manager, 'posts:edit', 'edit in ' . ($active ?? 'the platform'));
            self::assertSame([], \array_values(\array_filter(self::kept($manager, 'posts:view'), static fn (string $title): bool => \in_array($title, ['o2', 'b1'], true))));
        }
    }

    /**
     * A deny a tenant attaches to its own record applies when the record is
     * admitted from outside at platform scope; one it attaches for itself alone
     * does not apply to a record below it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOwnTenantDenyAppliesAtPlatformScope(): void
    {
        [$user, $tenants] = $this->tree();

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        $deny = self::storedPolicy('own-deny', [['effect' => 'deny', 'actions' => ['posts:view']]]);
        $rows = TenantScopedPost::query()->whereIn('title', ['o2', 'b1'])->pluck('id', 'title')->all();

        $service = app(ResourcePolicyService::class);

        foreach (['o2', 'b1'] as $title) {
            $id = $rows[$title] ?? null;

            $service->attach($deny, [TenantScopedPost::class, \is_scalar($id) ? (string) $id : ''], $tenants['o2'], false);
        }

        $manager = $this->resolveRequest($user, $tenants['o1']);

        self::assertAgrees($manager, 'posts:view', 'view in o1');
        self::assertNotContains('o2', self::kept($manager, 'posts:view'));
        self::assertContains('b1', self::kept($manager, 'posts:view'));
    }

    /**
     * At exactly the limits the classes are cut: four anchors (the active
     * tenant and three others) under `max_anchors` of four, and the nine
     * classes they make under `max_scopes` of nine; one fewer of either is
     * refused, naming the limit. A platform-wide grant counts two classes more
     * for each tenant a row admitted from outside reads, and one more for the
     * rows of none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLimitsHoldAtTheirBoundaries(): void
    {
        [$user, $tenants] = $this->tree();
        $config           = config();

        foreach (['a1', 'a2', 's1'] as $id) {
            $user->givePermission(Permission::firstOrCreate(['name' => 'posts:view']), null, $tenants[$id]);
        }

        $manager = $this->resolveRequest($user, $tenants['o1']);

        $config->set('authorization.query_scoping.max_anchors', 4);

        self::assertCount(9, self::classes($manager, new TenantScopedPost));

        $config->set('authorization.query_scoping.max_anchors', 3);

        self::assertSame('authorization.query_scoping.max_anchors', self::refusal($manager)->refusals[0]->key);

        $config->set('authorization.query_scoping.max_anchors', 4);
        $config->set('authorization.query_scoping.max_scopes', 9);

        self::assertCount(9, self::classes($manager, new TenantScopedPost));

        $config->set('authorization.query_scoping.max_scopes', 8);

        self::assertSame('authorization.query_scoping.max_scopes', self::refusal($manager)->refusals[0]->key);

        $user->givePermission(Permission::firstOrCreate(['name' => 'posts:view']));
        self::railAt(['o2']);

        $config->set('authorization.query_scoping.max_anchors', 5);
        $config->set('authorization.query_scoping.max_scopes', 12);

        self::assertCount(12, self::classes($manager, new TenantScopedPost));

        $config->set('authorization.query_scoping.max_scopes', 11);

        self::assertSame('authorization.query_scoping.max_scopes', self::refusal($manager)->refusals[0]->key);
    }

    /**
     * The classes are counted before any is cut, so a query over `max_scopes`
     * is refused without asking the tree where each anchor lies.
     *
     * @return void
     */
    public function testTheClassesAreCountedBeforeTheTreeIsWalked(): void
    {
        [$user, $tenants] = $this->tree();

        foreach (['a1', 'a2', 's1'] as $id) {
            $user->givePermission(Permission::firstOrCreate(['name' => 'posts:view']), null, $tenants[$id]);
        }

        $manager = $this->resolveRequest($user, $tenants['o1']);
        $tree    = new CountingTenantTree(new ClosureTenantTree);

        $this->app?->instance(TenantTree::class, $tree);
        $this->app?->make(ConfigRepository::class)->set('authorization.query_scoping.max_scopes', 8);

        self::refusal($manager);

        // Only the active tenant's own chain is read, and where each other
        // anchor lies asked once.
        self::assertSame(1, $tree->ancestorsRead);
        self::assertSame(3, $tree->withinAsked);

        $this->app?->make(ConfigRepository::class)->set('authorization.query_scoping.max_scopes', 16);

        self::assertCount(9, self::classes($manager, new TenantScopedPost));
        self::assertSame(1 + 1 + 4, $tree->ancestorsRead);
        self::assertSame(3 + 3, $tree->withinAsked);
    }

    /**
     * A deny attached in a sibling organisation to the type, not to a record,
     * applies to that organisation's rows and its subtree's when a
     * platform-wide grant admits them, as `check()` applies it, and leaves the
     * active organisation's rows alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOwnTenantTypeDenyAppliesToAdmittedRows(): void
    {
        [$user, $tenants] = $this->tree();

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        $deny = self::storedPolicy('own-type-deny', [['effect' => 'deny', 'actions' => ['posts:view']]]);

        app(ResourcePolicyService::class)->attach($deny, TenantScopedPost::class, $tenants['o2']);

        $manager = $this->resolveRequest($user, $tenants['o1']);
        $kept    = self::kept($manager, 'posts:view');

        self::assertAgrees($manager, 'posts:view', 'view in o1');
        self::assertNotContains('o2', $kept);
        self::assertNotContains('b1', $kept);
        self::assertContains('o1', $kept);
        self::assertContains('s1', $kept);
    }

    /**
     * A row below the active tenant whose tenant id is longer than any tenant
     * can be, which the tree still places in the subtree, is kept by no class,
     * since the tenant resolver cannot read it.
     *
     * @return void
     */
    public function testARowBelowAnAnchorWithAnUnreadableTenantIsNotKept(): void
    {
        if (DB::connection()->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite stores a tenant id longer than the closure table declares.');
        }

        [$user, $tenants] = $this->tree();

        $user->givePermission(Permission::create(['name' => 'posts:view']), null, $tenants['o1']);

        $long = \str_repeat('t', 192);

        DB::table(ClosureTenantTree::TABLE)->insert([
            'ancestor_type'   => self::tenantType(),
            'ancestor_id'     => 'o1',
            'descendant_type' => self::tenantType(),
            'descendant_id'   => $long,
            'depth'           => 1,
        ]);
        TenantScopedPost::query()->create(['title' => 'long', 'tenant_type' => self::tenantType(), 'tenant_id' => $long]);

        $kept = self::kept($this->resolveRequest($user, $tenants['o1']), 'posts:view');

        self::assertNotContains('long', $kept);
        self::assertContains('s1', $kept);
    }

    /**
     * Under the flat tree each anchor makes one class: an active tenant's
     * request makes two, its own and none; a platform-wide grant with no active
     * tenant makes one for each tenant a row admitted from outside reads, and
     * one for the rows of no such tenant. The limits hold at their boundaries,
     * one not set takes its default, at most 16 classes and 64 anchors, and one
     * that is not a whole number of at least one is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFlatTreesClassesAreCountedOneForEachAnchor(): void
    {
        $user   = StubIdentity::create(['id' => 'u1']);
        $config = config();
        $active = $this->resolveRequest($user, new Reference(self::tenantType(), 'o1'));

        $config->set('authorization.query_scoping.max_scopes', 2);

        self::assertCount(2, self::classes($active, new TenantScopedPost));

        $config->set('authorization.query_scoping.max_scopes', 1);

        self::assertSame('authorization.query_scoping.max_scopes', self::refusal($active)->refusals[0]->key);

        $user->givePermission(Permission::create(['name' => 'posts:view']));
        self::railAt(['o2', 'b1']);

        $platform = $this->resolveRequest($user);

        $config->set('authorization.query_scoping.max_scopes', 4);
        $config->set('authorization.query_scoping.max_anchors', 2);

        self::assertEqualsCanonicalizing([[null, false, false], ['o2', false, true], ['b1', false, true], [null, false, true]], \array_map(
            static fn (array $class): array => \array_slice($class, 1),
            self::described(self::classes($platform, new TenantScopedPost)),
        ));

        $config->set('authorization.query_scoping.max_anchors', 1);

        self::assertSame('authorization.query_scoping.max_anchors', self::refusal($platform)->refusals[0]->key);

        $config->set('authorization.query_scoping.max_anchors', 2);
        $config->set('authorization.query_scoping.max_scopes', 3);

        self::assertSame('authorization.query_scoping.max_scopes', self::refusal($platform)->refusals[0]->key);

        foreach (['max_scopes', 'max_anchors'] as $limit) {
            $config->set('authorization.query_scoping', [$limit => 'many']);

            try {
                self::classes($platform, new TenantScopedPost);

                self::fail("The limit {$limit} was not refused.");
            } catch (InvalidAuthorizationConfigException $exception) {
                self::assertSame("authorization.query_scoping.{$limit}", $exception->getConfigKey());
            }
        }

        $config->set('authorization.query_scoping', []);

        $rails = \array_map(static fn (int $index): string => "t{$index}", \range(1, 63));

        self::railAt(\array_slice($rails, 0, 12));

        self::assertCount(16, self::classes($platform, new TenantScopedPost));

        self::railAt([$rails[12]]);

        self::assertSame('authorization.query_scoping.max_scopes', self::refusal($platform)->refusals[0]->key);

        $config->set('authorization.query_scoping.max_scopes', 100);
        self::railAt(\array_slice($rails, 13, 49));

        self::assertCount(66, self::classes($platform, new TenantScopedPost));

        self::railAt([$rails[62]]);

        self::assertSame('authorization.query_scoping.max_anchors', self::refusal($platform)->refusals[0]->key);
    }

    /**
     * Put a guardrail at each tenant, so a row admitted from outside reads it.
     *
     * @param  list<string>  $ids
     * @return void
     */
    private static function railAt(array $ids): void
    {
        $policy = self::storedPolicy('rail-' . Str::random(6), [])->getKey();

        foreach ($ids as $id) {
            DB::table('guardrails')->insert(['policy_id' => $policy, 'tenant_type' => self::tenantType(), 'tenant_id' => $id]);
        }
    }

    /**
     * Build the tree, one post in each tenant and one of no tenant, and the
     * subject; return the subject and the tenants by id.
     *
     * @return array{\Tests\Feature\Stubs\StubIdentity, array<string, \Illuminate\Database\Eloquent\Model>}
     */
    private function tree(): array
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        /** @var array<string, \Illuminate\Database\Eloquent\Model> $tenants */
        $tenants = [];
        $parents = ['a1' => 'o1', 'a2' => 'o1', 's1' => 'a1', 'b1' => 'o2'];

        foreach (self::TENANTS as $id) {
            $tenants[$id] = StubTenant::query()->create(['id' => $id]);

            $parent = isset($parents[$id]) ? ($tenants[$parents[$id]] ?? null) : null;

            ClosureTenantTree::add(Reference::of($tenants[$id]), $parent === null ? null : Reference::of($parent));
            TenantScopedPost::query()->create(['title' => $id, 'tenant_type' => self::tenantType(), 'tenant_id' => $id]);
        }

        TenantScopedPost::query()->create(['title' => 'none']);

        return [StubIdentity::create(['id' => 'u1']), $tenants];
    }

    /**
     * Assert that the scope keeps exactly the posts `check()` allows.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  string  $action
     * @param  string  $message
     * @return void
     */
    private static function assertAgrees(AuthorizationManager $manager, string $action, string $message): void
    {
        $allowed = [];

        foreach (TenantScopedPost::query()->orderBy('id')->get() as $post) {
            $title = $post->getAttribute('title');

            if (!$manager->can($action, $post) || !\is_string($title)) {
                continue;
            }

            $allowed[] = $title;
        }

        self::assertSame($allowed, self::kept($manager, $action), $message);
    }

    /**
     * Return the titles of the posts the scope keeps, in order.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  string  $action
     * @return list<string>
     */
    private static function kept(AuthorizationManager $manager, string $action): array
    {
        /** @var list<string> */
        return TenantScopedPost::query()->whereAuthorized($action, [], $manager)->orderBy('id')->pluck('title')->all(); // @phpstan-ignore method.notFound
    }

    /**
     * Return the classes of the model's rows for the manager's subject.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $action
     * @return list<\SineMacula\Laravel\Authorization\Query\ScopeClass>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private static function classes(AuthorizationManager $manager, Model $model, string $action = 'posts:view'): array
    {
        /** @var \SineMacula\Laravel\Authorization\Subject $subject */
        $subject   = $manager->currentSubject();
        $inspector = new SchemaInspector;

        return ScopeClasses::of(ResourceShape::of($model, $action, $inspector), $subject, $action, $inspector);
    }

    /**
     * Return the refusal splitting the posts' rows throws.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @return \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private static function refusal(AuthorizationManager $manager): QueryScopeRefusedException
    {
        return self::refusalOf(static fn (): array => self::classes($manager, new TenantScopedPost));
    }

    /**
     * Return each class as its membership, tenant, whether it stands below and
     * whether it is admitted.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Query\ScopeClass>  $classes
     * @return list<array{string, string|null, bool, bool}>
     */
    private static function described(array $classes): array
    {
        return \array_map(static fn (ScopeClass $class): array => [$class->membership, $class->tenant?->id, $class->isBelow, $class->isAdmitted], $classes);
    }

    /**
     * Return the tenants' morph type.
     *
     * @return string
     */
    private static function tenantType(): string
    {
        return (new StubTenant)->getMorphClass();
    }
}
