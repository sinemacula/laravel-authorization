<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Carbon\CarbonImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\AffectedHolders;
use SineMacula\Laravel\Authorization\Administration\DocumentComparison;
use SineMacula\Laravel\Authorization\Enums\DependencyPhase;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\RecordsRowLocks;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `AffectedHolders`: the principals and identities a change
 * to a shared definition reaches, read set by set and bounded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AffectedHolders::class)]
final class AffectedHoldersTest extends TestCase
{
    use CatchesRefusals, RecordsRowLocks;

    /**
     * A role reaches its grantees and those of every role below it, in any
     * tenant, each once; with the hierarchy disabled, its own alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleReachesItsHoldersAndThoseOfTheRolesBelowIt(): void
    {
        $role  = Role::query()->create(['name' => 'editor']);
        $below = Role::query()->create(['name' => 'junior', 'parent_id' => $role->id]);
        $least = Role::query()->create(['name' => 'least', 'parent_id' => $below->id]);

        self::grants()->grantRole(self::user('one'), $role);
        self::grants()->grantRole(self::user('one'), $below, tenant: new Reference('tenant', 'a'));
        self::grants()->grantRole(self::user('two'), $least);

        self::assertSame(['one', 'two'], self::ids(AffectedHolders::none()->ofRoles([$role->id])->holders()));
        self::assertSame(['two'], self::ids(AffectedHolders::none()->ofRoles([$least->id])->holders()));
        self::assertSame([], AffectedHolders::none()->ofRoles([])->holders());

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame(['one'], self::ids(AffectedHolders::none()->ofRoles([$role->id])->holders()));
        self::assertSame(['one', 'two'], self::ids(AffectedHolders::none()->ofRoles([$role->id, $least->id])->holders()));
    }

    /**
     * Inside a delegated operation, every set read is locked and pinned as the
     * operation's holders, the roles below a role with every role whose parent
     * is one of them, so a holder granted, or a role put below one, before the
     * write fails validation; outside one, nothing is locked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideADelegatedOperationTheHoldersArePinned(): void
    {
        $role       = Role::query()->create(['name' => 'editor']);
        $permission = Permission::query()->create(['name' => 'posts:edit']);
        $policy     = Policy::query()->create(['name' => 'shared', 'document' => ['statements' => []]]);

        self::grants()->grantRole(self::user('one'), $role);

        $locks = $this->recordRowLocks();

        AffectedHolders::none()->ofRoles([$role->id]);

        self::assertSame([], $locks->getArrayCopy());

        $operation = new Operation('op', new Reference('user', 'admin'), CarbonImmutable::now('UTC'), false);

        $failures = OperationScope::run($operation, static function () use ($role, $permission, $policy, $locks): array {
            AffectedHolders::none()->ofRoles([$role->id])->ofPermission($permission)->ofPolicy($policy, []);

            $pins     = OperationScope::pins();
            $phase    = $pins?->phase();
            $tables   = \array_values(\array_unique(\array_column($locks->getArrayCopy(), 0)));
            $failures = [$phase, $tables];

            $pins?->validate();

            Role::query()->create(['name' => 'junior', 'parent_id' => $role->id]);

            try {
                $pins?->validate();
            } catch (DependencyChangedException $exception) {
                $failures[] = $exception->getMessage();
            }

            return $failures;
        });

        self::assertSame(DependencyPhase::HOLDERS, $failures[0]);
        self::assertSame(
            ['roles', 'authorizable_roles', 'authorizable_permissions', 'role_permissions', 'authorizable_policies', 'authorizable_boundaries', 'resource_policies'],
            $failures[1],
        );
        self::assertSame('The rows of [roles] a delegated decision read changed before the write.', $failures[2] ?? null);
    }

    /**
     * Inside a delegated operation, a set of holders over the impact limit is
     * never locked: the change is refused as it is; a set within it is locked,
     * a holder's every row with it, and read from the rows as locked, each
     * holder and each key once, so a holder with rows in several tenants, or a
     * role a policy is attached to in several, counts once, and nothing it read
     * changes before the write.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideADelegatedOperationOnlyASetWithinTheLimitIsLocked(): void
    {
        config(['authorization.administration.max_impact' => 1]);

        $crowded = Role::query()->create(['name' => 'crowded']);
        $single  = Role::query()->create(['name' => 'single']);
        $policy  = Policy::query()->create(['name' => 'shared', 'document' => ['statements' => []]]);

        self::grants()->grantRole(self::user('one'), $crowded);
        self::grants()->grantRole(self::user('two'), $crowded);

        foreach ([null, new Reference('stub_tenant', 't1'), new Reference('stub_tenant', 't2')] as $tenant) {
            self::grants()->grantRole(self::user('three'), $single, tenant: $tenant);
            self::grants()->attachPolicy($single, $policy, tenant: $tenant);
        }

        $locks     = $this->recordRowLocks();
        $operation = new Operation('op', new Reference('user', 'admin'), CarbonImmutable::now('UTC'), false);

        [$crowd, $three, $roles] = OperationScope::run($operation, static function () use ($crowded, $single, $policy): array {
            $outcome = [
                AffectedHolders::none()->ofRoles([$crowded->id])->holders(),
                self::ids(AffectedHolders::none()->ofRoles([$single->id])->holders()),
                AffectedHolders::none()->ofPolicy($policy, [])->holders(),
            ];

            OperationScope::delegatedPins()->validate();

            return $outcome;
        });

        $grantees = \array_values(\array_filter($locks->getArrayCopy(), static fn (array $lock): bool => $lock[0] === 'authorizable_roles'));

        self::assertNull($crowd);
        self::assertSame(['three'], $three);
        self::assertSame(['three'], self::ids($roles));
        self::assertNotContains(['authorizable_roles', [$crowded->id]], $grantees);
        self::assertContains(['authorizable_roles', [$single->id]], $grantees);
    }

    /**
     * Inside a delegated operation, whether a policy is attached to a resource
     * is read from one attachment, locked, never from every one, so the last
     * attachment detached, or a first one made, before the write is noticed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideADelegatedOperationOneResourceAttachmentIsLocked(): void
    {
        $policy = Policy::query()->create(['name' => 'shared', 'document' => ['statements' => []]]);

        foreach (['1', '2', '3'] as $id) {
            DB::table('resource_policies')->insert(['policy_id' => $policy->getKey(), 'resource_type' => 'post', 'resource_id' => $id]);
        }

        /** @var \ArrayObject<int, string> $reads */
        $reads     = new \ArrayObject;
        $operation = new Operation('op', new Reference('user', 'admin'), CarbonImmutable::now('UTC'), false);

        DB::listen(static fn ($query) => \str_contains($query->sql, 'resource_policies') ? $reads->append(\str_replace(['"', '`'], '', $query->sql)) : null);

        $changed = OperationScope::run($operation, static function () use ($policy): bool {
            AffectedHolders::none()->ofPolicy($policy, []);

            $pins = OperationScope::delegatedPins();

            DB::table('resource_policies')->where('resource_id', '1')->delete();

            $pins->validate();

            DB::table('resource_policies')->delete();

            try {
                $pins->validate();
            } catch (DependencyChangedException) {
                return true;
            }

            return false;
        });

        self::assertTrue($changed);
        self::assertStringContainsString('select policy_id from resource_policies where policy_id = ? limit 1', $reads[0] ?? '');
    }

    /**
     * With the hierarchy disabled, the roles named are locked all the same, so
     * a grant of one, which locks its row, meets the operation on it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithTheHierarchyDisabledTheRolesNamedAreLocked(): void
    {
        config(['authorization.hierarchy.enabled' => false]);

        $role      = Role::query()->create(['name' => 'editor']);
        $locks     = $this->recordRowLocks();
        $operation = new Operation('op', new Reference('user', 'admin'), CarbonImmutable::now('UTC'), false);

        $changed = OperationScope::run($operation, static function () use ($role): bool {
            AffectedHolders::none()->ofRoles([$role->id]);

            DB::table('roles')->where('id', $role->id)->update(['rank' => 3]);

            try {
                OperationScope::delegatedPins()->validate();
            } catch (DependencyChangedException) {
                return true;
            }

            return false;
        });

        self::assertTrue($changed);
        self::assertSame(['roles', [$role->id]], $locks[0] ?? null);
    }

    /**
     * A permission reaches its grantees and the holders of every role that
     * carries it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPermissionReachesItsGranteesAndTheHoldersOfItsRoles(): void
    {
        $edit = Permission::query()->create(['name' => 'posts:edit']);
        $role = Role::query()->create(['name' => 'editor']);

        self::grants()->grantPermission(self::user('direct'), $edit);
        RoleService::instance()?->grantPermission($role, $edit);
        self::grants()->grantRole(self::user('through'), $role);
        self::grants()->grantRole(self::user('other'), Role::query()->create(['name' => 'other']));

        self::assertSame(['direct', 'through'], self::ids(AffectedHolders::none()->ofPermission($edit)->holders()));

        $writer = Role::query()->create(['name' => 'writer']);

        RoleService::instance()?->grantPermission($writer, $edit);
        self::grants()->grantRole(self::user('writing'), $writer);

        self::assertSame(['direct', 'through', 'writing'], self::ids(AffectedHolders::none()->ofPermission($edit)->holders()));
    }

    /**
     * A policy reaches the subjects it is attached to or bounds, the holders of
     * every role it is attached to, and, when it is attached to a resource, the
     * principals each document's allows name, the holders of a role a selector
     * names included; a document that cannot be read cannot be bounded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyReachesEveryoneItIsAttachedToOrNames(): void
    {
        $role   = Role::query()->create(['name' => 'editor']);
        $named  = Role::query()->create(['name' => 'named']);
        $policy = Policy::create(['name' => 'sharing', 'document' => ['statements' => [[
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'principals' => [self::selector(self::user('principal')), 'role:' . $named->id],
        ]]]]);
        $plain = Policy::create(['name' => 'plain', 'document' => ['statements' => []]]);

        self::grants()->attachPolicy(self::user('attached'), $plain);
        self::grants()->attachPolicy($role, $plain);
        self::grants()->grantRole(self::user('holder'), $role);
        BoundaryService::instance()?->set(self::user('bounded'), $plain);

        self::assertSame(['attached', 'bounded', 'holder'], self::ids(AffectedHolders::none()->ofPolicy($plain, [DocumentComparison::read($plain->document)])->holders()));

        self::grants()->grantRole(self::user('selected'), $named);

        self::assertSame([], AffectedHolders::none()->ofPolicy($policy, [DocumentComparison::read($policy->document)])->holders());

        ResourcePolicyService::instance()?->attach($policy, ['posts', 7]);

        self::assertSame(['principal', 'selected'], self::ids(AffectedHolders::none()->ofPolicy($policy, [DocumentComparison::read($policy->document)])->holders()));
        self::assertNull(AffectedHolders::none()->ofPolicy($policy, [null])->holders());
    }

    /**
     * The principals a document's allows name are read as references, each by
     * its type and key, past any role a selector names, a deny naming none; a
     * document that cannot be read cannot be bounded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalsOfADocumentAreItsAllowsSelectors(): void
    {
        $role     = Role::query()->create(['name' => 'editor']);
        $document = DocumentComparison::read(['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1', 'role:' . $role->id, 'machine:1', 'machine:a:b']],
            ['effect' => 'deny', 'actions' => ['posts:read']],
        ]]);

        $holders = AffectedHolders::none()->ofPrincipals($document)->holders() ?? [];

        self::assertEquals([new Reference('user', '1'), new Reference('machine', '1'), new Reference('machine', 'a:b')], $holders);
        self::assertNull(AffectedHolders::none()->ofPrincipals(null)->holders());
    }

    /**
     * The set holds at most `authorization.administration.max_impact` holders:
     * one more puts it over its limit, as does one role more than it, a limit
     * written as the environment gives a whole number is read as one, an unset
     * limit is the default, and an invalid one is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSetIsBoundedByTheImpactLimit(): void
    {
        $role = Role::query()->create(['name' => 'editor']);
        $edit = Permission::query()->create(['name' => 'posts:edit']);

        foreach (['one', 'two', 'three'] as $id) {
            self::grants()->grantRole(self::user($id), $role);
        }

        config(['authorization.administration.max_impact' => 3]);

        self::assertCount(3, AffectedHolders::none()->ofRoles([$role->id])->holders() ?? []);

        config(['authorization.administration.max_impact' => 2]);

        self::assertNull(AffectedHolders::none()->ofRoles([$role->id])->holders());
        self::assertNull(AffectedHolders::none()->ofRoles([$role->id])->ofPermission($edit)->holders());

        foreach (['a', 'b', 'c'] as $name) {
            RoleService::instance()?->grantPermission(Role::query()->create(['name' => $name]), $edit);
        }

        self::assertNull(AffectedHolders::none()->ofPermission($edit)->holders());

        config(['authorization.administration.max_impact' => '2']);

        self::assertNull(self::holdersOf($role));

        config(['authorization.administration.max_impact' => 'many']);

        self::assertInstanceOf(InvalidAuthorizationConfigException::class, self::refusalOf(static fn (): ?array => self::holdersOf($role)));
        self::assertSame(1000, AffectedHolders::DEFAULT_LIMIT);
    }

    /**
     * The limit counts distinct holders: a holder one set names twice, or two
     * sets both name, never uses up the room of one not read yet, so a set at
     * the limit holds every holder, and one over it is always over, whichever
     * set the extra holder comes from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLimitCountsDistinctHolders(): void
    {
        $edit   = Permission::query()->create(['name' => 'posts:edit']);
        $editor = Role::query()->create(['name' => 'editor']);

        foreach (['a', 'b'] as $id) {
            self::grants()->grantPermission(self::user($id), $edit);
        }

        RoleService::instance()?->grantPermission($editor, $edit);

        foreach (['a', 'b', 'c'] as $id) {
            self::grants()->grantRole(self::user($id), $editor);
        }

        self::grants()->grantRole(self::user('a'), $editor, tenant: new Reference('tenant', 'a'));

        config(['authorization.administration.max_impact' => 3]);

        self::assertSame(['a', 'b', 'c'], self::ids(AffectedHolders::none()->ofPermission($edit)->holders()));
        self::assertSame(['a', 'b', 'c'], self::ids(AffectedHolders::none()->ofRoles([$editor->id])->holders()));

        self::grants()->grantRole(self::user('senior'), $editor);

        self::assertNull(AffectedHolders::none()->ofPermission($edit)->holders());

        config(['authorization.administration.max_impact' => 4]);

        self::assertSame(['a', 'b', 'c', 'senior'], self::ids(AffectedHolders::none()->ofPermission($edit)->holders()));

        $view = Permission::query()->create(['name' => 'posts:view']);
        $role = Role::query()->create(['name' => 'viewer']);

        foreach (['a', 'b', 'c'] as $id) {
            self::grants()->grantPermission(self::user($id), $view);
        }

        RoleService::instance()?->grantPermission($role, $view);
        self::grants()->grantRole(self::user('a'), $role);
        self::grants()->grantRole(self::user('outsider'), $role);

        config(['authorization.administration.max_impact' => 3]);

        self::assertNull(AffectedHolders::none()->ofPermission($view)->holders());
    }

    /**
     * The limit counts distinct holders of a policy too: subjects it is both
     * attached to and bounds count once, and one more than the limit, from
     * either set, puts it over.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicysHoldersAreCountedOnce(): void
    {
        $plain = Policy::create(['name' => 'plain', 'document' => ['statements' => []]]);

        foreach (['p', 'q'] as $id) {
            self::grants()->attachPolicy(self::user($id), $plain);
            BoundaryService::instance()?->set(self::user($id), $plain);
        }

        $document = [DocumentComparison::read($plain->document)];

        config(['authorization.administration.max_impact' => 2]);

        self::assertSame(['p', 'q'], self::ids(AffectedHolders::none()->ofPolicy($plain, $document)->holders()));

        BoundaryService::instance()?->set(self::user('r'), $plain);

        self::assertNull(AffectedHolders::none()->ofPolicy($plain, $document)->holders());

        config(['authorization.administration.max_impact' => 3]);

        self::assertSame(['p', 'q', 'r'], self::ids(AffectedHolders::none()->ofPolicy($plain, $document)->holders()));
    }

    /**
     * At the edges of the limit: a limit of one holds one role, and no holder
     * at all, without being over; each read asks for one row more than the
     * limit, and a set over it reads nothing more; a limit that is no positive
     * whole number is refused, never read as the default.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLimitHoldsAtItsEdges(): void
    {
        $role = Role::query()->create(['name' => 'editor']);
        $lone = Permission::query()->create(['name' => 'posts:lone']);

        RoleService::instance()?->grantPermission(Role::query()->create(['name' => 'empty']), $lone);

        foreach (['one', 'two', 'three'] as $id) {
            self::grants()->grantRole(self::user($id), $role);
        }

        config(['authorization.administration.max_impact' => 1]);

        self::assertSame(1, AffectedHolders::limit());
        self::assertSame([], AffectedHolders::none()->ofPermission($lone)->holders());
        self::assertNull(self::holdersOf($role));

        $over = AffectedHolders::none()->ofPrincipals(null);

        DB::flushQueryLog();
        DB::enableQueryLog();

        $over->ofRoles([$role->id]);
        $over->ofPermission($lone);
        AffectedHolders::none()->ofRoles([]);

        $queries = \count(DB::getQueryLog());

        AffectedHolders::none()->ofPermission($lone);

        $reads = \array_column(DB::getQueryLog(), 'query');

        DB::disableQueryLog();

        self::assertSame(0, $queries);
        self::assertCount(4, $reads);
        self::assertStringEndsWith('limit 2', $reads[0]);
        self::assertStringEndsWith('limit 2', $reads[1]);
        self::assertStringEndsWith('limit 2', $reads[3]);

        foreach ([0, -1] as $limit) {
            config(['authorization.administration.max_impact' => $limit]);

            self::assertInstanceOf(InvalidAuthorizationConfigException::class, self::refusalOf(static fn (): int => AffectedHolders::limit()));
            self::assertInstanceOf(InvalidAuthorizationConfigException::class, self::refusalOf(static fn (): ?array => self::holdersOf($role)));
        }
    }

    /**
     * Each set is read from the table `authorization.tables` names under its
     * key, so a table named there that does not exist cannot be read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachSetIsReadFromTheTableTheConfigNames(): void
    {
        $role = Role::query()->create(['name' => 'editor']);

        self::grants()->grantRole(self::user('one'), $role);

        config(['authorization.tables.authorizable_roles' => 'missing_authorizable_roles']);

        self::assertInstanceOf(QueryException::class, self::refusalOf(static fn (): ?array => self::holdersOf($role)));
    }

    /**
     * Return the holders of the role, read afresh under the limit in place.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>|null
     */
    private static function holdersOf(Role $role): ?array
    {
        return AffectedHolders::none()->ofRoles([$role->id])->holders();
    }

    /**
     * Return the keys of the holders, sorted, or null for none.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>|null  $holders
     * @return list<string>|null
     */
    private static function ids(?array $holders): ?array
    {
        if ($holders === null) {
            return null;
        }

        $ids = \array_map(static fn (Reference $holder): string => $holder->id, $holders);

        \sort($ids);

        return $ids;
    }

    /**
     * Return the principal selector naming the identity.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @return string
     */
    private static function selector(StubIdentity $identity): string
    {
        $reference = Reference::of($identity);

        return $reference->type . ':' . $reference->id;
    }

    /**
     * Return the identity with the id, created on first use.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function user(string $id): StubIdentity
    {
        return StubIdentity::query()->firstOrCreate(['id' => $id]);
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
}
