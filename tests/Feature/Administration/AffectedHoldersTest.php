<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\AffectedHolders;
use SineMacula\Laravel\Authorization\Administration\DocumentComparison;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Reference;
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
     * The principals a document's allows name are read as references, a deny
     * naming none; a document that cannot be read cannot be bounded.
     *
     * @return void
     */
    public function testThePrincipalsOfADocumentAreItsAllowsSelectors(): void
    {
        $document = DocumentComparison::read(['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1', 'machine:a:b']],
            ['effect' => 'deny', 'actions' => ['posts:read']],
        ]]);

        $holders = AffectedHolders::none()->ofPrincipals($document)->holders() ?? [];

        self::assertEquals([new Reference('user', '1'), new Reference('machine', 'a:b')], $holders);
        self::assertNull(AffectedHolders::none()->ofPrincipals(null)->holders());
    }

    /**
     * The set holds at most `authorization.administration.max_impact` holders:
     * one more puts it over its limit, as does one role more than it, and an
     * unset or invalid limit is the default.
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

        config(['authorization.administration.max_impact' => 'many']);

        self::assertCount(3, self::holdersOf($role) ?? []);
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
     * at all, without being over; a set over it reads nothing more; a limit
     * that is no positive whole number is the default.
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
        AffectedHolders::none()->ofRoles([]);

        $queries = \count(DB::getQueryLog());

        DB::disableQueryLog();

        self::assertSame(0, $queries);

        foreach ([0, -1] as $limit) {
            config(['authorization.administration.max_impact' => $limit]);

            self::assertSame(AffectedHolders::DEFAULT_LIMIT, AffectedHolders::limit());
            self::assertCount(3, self::holdersOf($role) ?? []);
        }
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
