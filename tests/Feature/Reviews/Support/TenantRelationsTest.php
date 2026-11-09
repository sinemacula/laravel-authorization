<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRows;
use SineMacula\Laravel\Authorization\Reviews\Support\TenantRelations;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ReviewsAccess;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\CountingTenantTree;
use Tests\Fixtures\QueryScoping\SubtreeQueryTree;
use Tests\TestCase;

/**
 * Feature tests for whether a role's grant and a policy attachment to the role
 * meet in some tenant: the tree asked in a fixed number of queries for the
 * grants and attachments read together, a chunk of grant tenants at a time, and
 * the same meeting written into a grant query.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(TenantRelations::class)]
final class TenantRelationsTest extends TestCase
{
    use ReviewsAccess;

    /**
     * Two scopes meet when either is the platform's, both name one tenant, or
     * one reaches below a tenant the other names or is below; the tree is asked
     * once for each pair nothing settled.
     *
     * @return void
     */
    public function testScopesMeetWhereTheyHoldTogether(): void
    {
        $counting = $this->countingTree();
        $meets    = new TenantRelations;

        self::assertTrue($meets->canHoldTogether(self::scope(null), self::scope('acct1', false)));
        self::assertTrue($meets->canHoldTogether(self::scope('acct1', false), self::scope(null, false)));
        self::assertTrue($meets->canHoldTogether(self::scope('acct1', false), self::scope('acct1', false)));
        self::assertTrue($meets->canHoldTogether(self::scope('org1'), self::scope('team1', false)));
        self::assertTrue($meets->canHoldTogether(self::scope('team1', false), self::scope('org1')));
        self::assertFalse($meets->canHoldTogether(self::scope('org1', false), self::scope('team1')));
        self::assertFalse($meets->canHoldTogether(self::scope('team1'), self::scope('org1', false)));
        self::assertFalse($meets->canHoldTogether(self::scope('acct1'), self::scope('acct2')));
        self::assertSame(0, $counting->ancestorsRead);

        $asked = $counting->withinAsked;

        $meets->canHoldTogether(self::scope('team1'), self::scope('org1', false));

        self::assertSame($asked, $counting->withinAsked);
    }

    /**
     * Once the grants and attachments are settled, whether they meet is
     * answered from the attachments' chains and the subtrees read, never by
     * asking the tree about a pair; a grant at the platform or with no tenant
     * to settle asks nothing at all.
     *
     * @return void
     */
    public function testSettledScopesMeetWithoutAskingTheTree(): void
    {
        $counting = $this->countingTree();
        $meets    = new TenantRelations;

        $grants      = [self::scope('team1', false), self::scope('acct2', false), self::scope('org1'), self::scope('org2'), self::scope('acct1', false)];
        $attachments = [self::scope('acct1'), self::scope('org1', false), self::scope(null)];

        $meets->settle($grants, $attachments);

        self::assertSame(2, $counting->ancestorsRead);

        $asked = $counting->withinAsked;
        $grid  = [];

        foreach ($attachments as $attachment) {
            $grid[] = \array_map(static fn (GrantScope $grant): bool => $meets->canHoldTogether($grant, $attachment), $grants);
        }

        self::assertSame([
            [true, false, true, false, true],
            [false, false, true, false, false],
            [true, true, true, true, true],
        ], $grid);
        self::assertSame($asked, $counting->withinAsked);

        $nothing = new TenantRelations;

        $nothing->settle([self::scope(null)], [self::scope('acct1')]);

        self::assertSame(2, $counting->ancestorsRead);
    }

    /**
     * A subtree is asked about a chunk of grant tenants at a time, so its
     * bindings never grow past a chunk, and a tenant in a later chunk is found
     * as one in the first is.
     *
     * @return void
     */
    public function testASubtreeIsAskedAboutAChunkOfTenantsAtATime(): void
    {
        $this->tree();

        $grants = [];

        for ($index = 0; $index < TenantRelations::CHUNK; $index++) {
            $grants[] = new GrantScope(self::tenant('stranger-' . $index), null, false);
        }

        $grants[] = self::scope('team1', false);

        $queries = [];

        DB::listen(static function (QueryExecuted $executed) use (&$queries): void {
            $queries[] = \count($executed->bindings);
        });

        $meets = new TenantRelations;

        $meets->settle($grants, [self::scope('acct1')]);

        $this->app?->make('events')->forget(QueryExecuted::class);

        self::assertCount(3, $queries);
        self::assertLessThanOrEqual(TenantRelations::CHUNK + 4, \max($queries));
        self::assertTrue($meets->canHoldTogether(self::scope('team1', false), self::scope('acct1')));
        self::assertFalse($meets->canHoldTogether($grants[0], self::scope('acct1')));
    }

    /**
     * A flat tree settles without a query: a tenant is within itself alone.
     *
     * @return void
     */
    public function testAFlatTreeIsSettledWithoutAQuery(): void
    {
        $this->app?->instance(TenantTree::class, new FlatTenantTree);

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $meets = new TenantRelations;

        $meets->settle([self::scope('a', false), self::scope('b')], [self::scope('a'), self::scope('c')]);

        self::assertSame(0, $queries);
        self::assertTrue($meets->canHoldTogether(self::scope('a', false), self::scope('a')));
        self::assertFalse($meets->canHoldTogether(self::scope('b', false), self::scope('a')));
        self::assertFalse($meets->canHoldTogether(self::scope('b'), self::scope('c')));
        self::assertSame(0, $queries);
    }

    /**
     * A grant query is limited to the grants that meet the attachment: the
     * platform's, the attachment's tenant's, one reaching below a tenant of the
     * attachment's chain, and, for an attachment reaching below, one in its
     * subtree; an attachment at the platform meets every grant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantQueryIsLimitedToTheGrantsThatMeet(): void
    {
        $this->seedGrants();

        $meets = new TenantRelations;

        self::assertEqualsCanonicalizing(['platform', 'org1', 'acct1', 'team1'], self::meeting($meets, self::scope('acct1')));
        self::assertEqualsCanonicalizing(['platform', 'org1', 'acct1'], self::meeting($meets, self::scope('acct1', false)));
        self::assertEqualsCanonicalizing(['platform', 'org1', 'org1-node', 'acct1', 'team1', 'acct2'], self::meeting($meets, self::scope('org1')));
        self::assertEqualsCanonicalizing(['platform', 'org1', 'org1-node', 'acct1', 'team1', 'acct2', 'org2'], self::meeting($meets, self::scope(null)));
        self::assertSame(['tenant', 'acct1'], [$meets->chainOf(self::tenant('acct1'))[0]->type, $meets->chainOf(self::tenant('acct1'))[0]->id]);
        self::assertSame(['acct1', 'org1'], \array_map(static fn (Reference $tenant): string => $tenant->id, $meets->chainOf(self::tenant('acct1'))));
    }

    /**
     * A subtree that cannot be nested, on another connection, keeps every grant
     * held in a tenant in the query, for the run to weigh one by one, and is
     * still asked about the grants' tenants on its own connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubtreeOnAnotherConnectionIsWeighedOneByOne(): void
    {
        $this->seedGrants();

        config()->set('database.connections.tenants', config('database.connections.' . DB::getDefaultConnection()));

        $this->app?->instance(TenantTree::class, new SubtreeQueryTree(static fn (Reference $tenant): Builder => DB::connection('tenants')->query()
            ->selectRaw('? as tenant_type, ? as tenant_id', [$tenant->type, $tenant->id])));

        $meets = new TenantRelations;

        self::assertEqualsCanonicalizing(['platform', 'org1', 'org1-node', 'acct1', 'team1', 'acct2', 'org2'], self::meeting($meets, self::scope('acct1')));

        $meets->settle([self::scope('team1', false), self::scope('acct1', false)], [self::scope('acct1')]);

        self::assertTrue($meets->canHoldTogether(self::scope('acct1', false), self::scope('acct1')));
        self::assertFalse($meets->canHoldTogether(self::scope('team1', false), self::scope('acct1')));
    }

    /**
     * A subtree that is no query is refused when it is read.
     *
     * @return void
     */
    public function testASubtreeThatIsNoQueryIsRefused(): void
    {
        $this->tree();

        $this->app?->instance(TenantTree::class, new SubtreeQueryTree(static fn (): Builder => (new StubIdentity)->roles()));

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('The tenant tree\'s subtree is not a query.');

        (new TenantRelations)->settle([self::scope('team1', false)], [self::scope('acct1')]);
    }

    /**
     * Bind a closure-table tree that counts what it is asked, and return it.
     *
     * @return \Tests\Fixtures\QueryScoping\CountingTenantTree
     */
    private function countingTree(): CountingTenantTree
    {
        $this->tree();

        $counting = new CountingTenantTree(new ClosureTenantTree);

        $this->app?->instance(TenantTree::class, $counting);

        return $counting;
    }

    /**
     * Seed the tree, and grant one role in each scope: the platform, a node of
     * the first organisation, its subtree, each account, the team and the
     * second organisation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function seedGrants(): void
    {
        $this->tree();

        $role = self::role('reviewed');

        self::grants()->grantRole(new Reference('u', 'platform'), $role);
        self::grants()->grantRole(new Reference('u', 'org1-node'), $role, tenant: self::tenant('org1'), includeSubtree: false);

        foreach (['org1', 'acct1', 'team1', 'acct2', 'org2'] as $tenant) {
            self::grants()->grantRole(new Reference('u', $tenant), $role, tenant: self::tenant($tenant));
        }
    }

    /**
     * Return the grantees of the role grants that meet the attachment.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\TenantRelations  $meets
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $attachment
     * @return list<string>
     */
    private static function meeting(TenantRelations $meets, GrantScope $attachment): array
    {
        $table = GrantTarget::ROLE->table();

        return \array_map(
            static fn (GrantRow $row): string => $row->grantee->id,
            GrantRows::all($meets->constrain(GrantRows::of(GrantTarget::ROLE), $table, $attachment), 'role'),
        );
    }

    /**
     * Return a scope in the tenant, or at the platform for none, reaching below
     * it unless told not to.
     *
     * @param  string|null  $tenant
     * @param  bool  $isSubtree
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    private static function scope(?string $tenant, bool $isSubtree = true): GrantScope
    {
        return new GrantScope($tenant === null ? null : self::tenant($tenant), null, $isSubtree);
    }
}
