<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Query\Processors\Processor;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Testing\Concerns\TenantTreeContract;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\TenantTrees\ClashingTenants;
use Tests\Fixtures\TenantTrees\KeyedTenantTree;
use Tests\Fixtures\TenantTrees\RootTypedTenantTree;
use Tests\Fixtures\TenantTrees\SkewedTenantTree;
use Tests\Fixtures\TenantTrees\TenantTreeContractHarness;
use Tests\TestCase;

/**
 * Feature tests for the tenant tree contract kit: it passes a tree that keeps
 * the contract, and fails one that breaks it, or a fixture that cannot test it,
 * naming the node and what is wrong.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(TenantTreeContract::class)]
final class TenantTreeContractTest extends TestCase
{
    /** @var string The failure for a tree claiming mixed types over a fixture that cannot catch a subtree confusing them. */
    private const string UNMIXED = 'The tenant tree claims mixed types, but no node of its fixture has both a node of another type below it, and a node below it, '
        . 'or itself, sharing its id with a node of another type outside it, so a subtree typing every tenant with its root\'s type, or matching tenants by '
        . 'id alone, could pass: add them, such as ["team","7"] below ["org","1"] and ["org","7"] outside it.';

    /** @var string The pairs below the first organisation of the clashing fixture, sorted, the organisation left out. */
    private const string BELOW = '["account","3"], ["team","1"], ["team","2"], ["team","7"]';

    /**
     * Seed the closure table with the fixture of clashing ids.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        ClashingTenants::seed();
    }

    /**
     * Every check passes a tree keeping the contract: the closure table over
     * clashing ids, claimed as mixed, on the package's connection or the
     * application's default named as null; and the flat tree over tenants whose
     * ids do not clash, mixed types not claimed by default.
     *
     * @return void
     */
    public function testTheKitPassesATreeKeepingTheContract(): void
    {
        $flat = [[new Reference('stub_tenant', '1'), null], [new Reference('stub_org', '2'), null]];

        foreach ([self::harness(new ClosureTenantTree), self::harness(new ClosureTenantTree, null), new TenantTreeContractHarness(new FlatTenantTree, $flat)] as $harness) {
            self::check($harness);
        }

        self::assertNull(TenantScope::currentTenant());
    }

    /**
     * A tree over tenants keyed by integers or UUIDs, typed columns its own
     * queries compare in their type, passes, the tenant outside the fixture
     * keyed as its tenants are: the largest integer plus one, or a new UUID.
     *
     * @return void
     */
    public function testTheKitPassesATreeKeyedByIntegersOrUuids(): void
    {
        // An organisation above a team sharing its id, above a team sharing its
        // id with an organisation at the top, which is above a third team.
        $clashing = static function (string $first, string $second, string $third): array {
            [$org, $team, $other] = [new Reference('org', $first), new Reference('team', $first), new Reference('org', $second)];

            return [[$org, null], [$team, $org], [new Reference('team', $second), $team], [$other, null], [new Reference('team', $third), $other]];
        };

        $fixtures = [
            KeyedTenantTree::NUMBERED => $clashing('1', '7', '12'),
            KeyedTenantTree::UUID     => $clashing('0b5e9c1e-8a51-4c1b-9f3e-2d1f4a6b7c80', '6f1d2c3b-4a59-4e8d-b7c6-a5f4e3d2c1b0', '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d'),
        ];

        foreach ($fixtures as $table => $nodes) {
            $tree = new KeyedTenantTree($table);

            $tree->seed($nodes);

            self::check(new TenantTreeContractHarness($tree, $nodes, isMixed: true));
        }

        $numbered = (new TenantTreeContractHarness(new KeyedTenantTree(KeyedTenantTree::NUMBERED), $fixtures[KeyedTenantTree::NUMBERED]))->outsideTenant();
        $uuid     = (new TenantTreeContractHarness(new KeyedTenantTree(KeyedTenantTree::UUID), $fixtures[KeyedTenantTree::UUID]))->outsideTenant();

        self::assertSame(['org', '13'], [$numbered->type, $numbered->id]);
        self::assertSame('org', $uuid->type);
        self::assertTrue(Str::isUuid($uuid->id));
        self::assertNotContains($uuid->id, \array_map(static fn (array $node): string => $node[0]->id, $fixtures[KeyedTenantTree::UUID]));
    }

    /**
     * A subtree written as an Eloquent query is read through its base query,
     * and one returning a pair more than once still passes, since the readers
     * ask it whether a pair exists.
     *
     * @return void
     */
    public function testTheKitPassesAnEloquentSubtreeAndRepeatedPairs(): void
    {
        $closure = new class extends Model {
            /** @var string|null The closure table. */
            protected $table = ClosureTenantTree::TABLE;
        };

        $eloquent = new SkewedTenantTree(subtree: static fn (Reference $tenant): Builder => $closure->newQuery()
            ->select(['descendant_type as tenant_type', 'descendant_id as tenant_id'])
            ->where('ancestor_type', $tenant->type)
            ->where('ancestor_id', $tenant->id));

        $repeated = new SkewedTenantTree(subtree: static fn (Reference $tenant): Builder => self::closureSubtree($tenant)->unionAll(self::closureSubtree($tenant)));

        self::check(self::harness($eloquent));
        self::check(self::harness($repeated));
    }

    /**
     * A fixture that is no tree fails: one with no tenant, one listing a tenant
     * twice, one naming a parent it does not hold, and one whose parents form a
     * cycle.
     *
     * @return void
     */
    public function testTheKitFailsAFixtureThatIsNoTree(): void
    {
        [$org, $team, $other] = [new Reference('org', '1'), new Reference('team', '1'), new Reference('org', '9')];

        $named = new Reference('acme/org', 'équipe');

        $failures = [
            'The tenant tree fixture holds no tenant.'                                  => [],
            'The tenant tree fixture lists ["org","1"] twice.'                          => [[$org, null], [$org, null]],
            'The tenant tree fixture lists ["acme/org","équipe"] twice.'                => [[$named, null], [$named, null]],
            'The parent ["org","9"] of ["team","1"] is not in the tenant tree fixture.' => [[$team, $other]],
            'The parents of ["org","1"] in the tenant tree fixture form a cycle.'       => [[$org, $team], [$team, $org]],
        ];

        foreach ($failures as $message => $nodes) {
            self::assertFails($message, (new TenantTreeContractHarness(new ClosureTenantTree, $nodes))->testTenantTreeFixtureIsATree(...));
        }
    }

    /**
     * A tree claiming mixed types fails on a fixture that cannot catch a
     * subtree confusing them: one with no tenant below another, one with no
     * tenant below one of another type, one whose tenants sharing an id are
     * both below one tenant, one with no ids shared, and one whose shared id
     * and tenant of another type below lie below different tenants. A fixture
     * with both below one tenant passes, and a tree not claiming mixed types
     * passes on any.
     *
     * @return void
     */
    public function testAMixedTypeClaimNeedsAFixtureThatCatchesConfusedTypes(): void
    {
        [$org1, $org2, $org3, $org7]             = \array_map(static fn (string $id): Reference => new Reference('org', $id), ['1', '2', '3', '7']);
        [$team1, $team2, $team3, $team5, $team7] = \array_map(static fn (string $id): Reference => new Reference('team', $id), ['1', '2', '3', '5', '7']);

        $fixtures = [
            [[$team1, null], [$team2, null], [$org1, null], [$org3, null]],
            [[$org1, null], [$org2, $org1], [$team1, null], [$team2, $team1]],
            [[$org1, null], [$team1, $org1]],
            [[$org1, null], [$team2, $org1], [$team3, null]],
            [[$org1, null], [$team5, $org1], [$org2, null], [$org3, $org2], [$team3, null]],
        ];

        foreach ($fixtures as $nodes) {
            $claimed = new TenantTreeContractHarness(new ClosureTenantTree, $nodes, isMixed: true);

            self::assertStringStartsWith(self::UNMIXED . "\n", self::failure($claimed->testTenantTreeFixtureIsATree(...)));

            (new TenantTreeContractHarness(new ClosureTenantTree, $nodes, isMixed: false))->testTenantTreeFixtureIsATree();
        }

        (new TenantTreeContractHarness(new ClosureTenantTree, [[$org1, null], [$team7, $org1], [$org7, null]], isMixed: true))->testTenantTreeFixtureIsATree();
    }

    /**
     * A tree typing every tenant of a subtree with the type asked about, and
     * finding them by its id alone, as an adapter over a tree keeping ids alone
     * would if it guessed, passes the subtree checks over single-type
     * hierarchies, which the kit refuses for a tree claiming mixed types, and
     * fails each of them over a fixture the kit accepts, naming the pairs
     * missing and extra.
     *
     * @return void
     */
    public function testTheKitFailsATreeTypingEveryTenantWithTheRootsType(): void
    {
        $tree = self::harness(new RootTypedTenantTree);

        // Nested against a row of each node, the extra tenants outside the
        // fixture, ["org","2"] and ["org","3"], meet no row.
        $missing = 'the subtree of ["org","1"] is missing ' . self::BELOW;

        self::assertFails('The ' . \substr($missing, 4) . ' and has ["org","2"], ["org","3"], ["org","7"] extra.', $tree->testTenantTreeSubtreeSelectsTheTypedSubtree(...));
        self::assertFails('Nested in a query, ' . $missing . ' and has ["org","7"] extra.', $tree->testTenantTreeSubtreeNestsInAQuery(...));
        self::assertFails(
            'In the tenant scope of ["org","9"], ' . $missing . ' and has ["org","2"], ["org","3"], ["org","7"] extra.',
            $tree->testTenantTreeSubtreeIgnoresTheTenantScope(...),
        );

        DB::table(ClosureTenantTree::TABLE)->delete();

        [$org1, $team1] = [new Reference('org', '1'), new Reference('team', '1')];

        $hierarchies = [[$org1, null], [new Reference('org', '2'), $org1], [$team1, null], [new Reference('team', '2'), $team1]];

        foreach ($hierarchies as [$node, $parent]) {
            ClosureTenantTree::add($node, $parent);
        }

        self::check(new TenantTreeContractHarness(new RootTypedTenantTree, $hierarchies));
        self::assertFails(self::UNMIXED, (new TenantTreeContractHarness(new RootTypedTenantTree, $hierarchies, isMixed: true))->testTenantTreeFixtureIsATree(...));
    }

    /**
     * Ancestors out of order, or with the tenant itself, fail, naming the
     * tenant.
     *
     * @return void
     */
    public function testTheKitFailsAncestorsThatAreNotTheParentChain(): void
    {
        $reversed = new SkewedTenantTree(ancestors: static fn (Reference $tenant): array => \array_reverse((new ClosureTenantTree)->ancestors($tenant)));
        $itself   = new SkewedTenantTree(ancestors: static fn (Reference $tenant): array => [$tenant, ...(new ClosureTenantTree)->ancestors($tenant)]);

        self::assertFails(
            'The ancestors of ["team","7"] are not its parent chain, nearest first, the tenant left out.',
            self::harness($reversed)->testTenantTreeAncestorsAreTheParentChain(...),
        );
        self::assertFails('The ancestors of ["org","1"] are not its parent chain', self::harness($itself)->testTenantTreeAncestorsAreTheParentChain(...));
    }

    /**
     * An `isWithin()` that confuses types sharing an id, that misses a tenant
     * below, or that holds for the tenant outside the fixture either way, the
     * kit's or the one a test case gives, fails, naming the pair.
     *
     * @return void
     */
    public function testTheKitFailsAnIsWithinThatIsNotTheSubtree(): void
    {
        $closure = new ClosureTenantTree;

        $same = static fn (Reference $tenant, Reference $ancestor): bool => $tenant->type === $ancestor->type && $tenant->id === $ancestor->id;
        $byId = static fn (Reference $tenant, Reference $ancestor): bool => $closure->isWithin($tenant, $ancestor)
            || ($tenant->id === $ancestor->id && $ancestor->type === 'org');
        $outsider = static fn (Reference $tenant, Reference $ancestor): bool => $closure->isWithin($tenant, $ancestor) || $tenant->id === '9';
        $above    = static fn (Reference $tenant, Reference $ancestor): bool => $closure->isWithin($tenant, $ancestor) || $ancestor->id === '9';

        $failures = [
            'isWithin(["team","1"], ["org","1"]) does not hold, though ["team","1"] is ["org","1"] or below it.' => $same,
            'isWithin(["team","7"], ["org","7"]) holds, though ["team","7"] is not ["org","7"] nor below it.'    => $byId,
            'isWithin(["org","9"], ["org","1"]) holds for a tenant outside the fixture.'                         => $outsider,
            'isWithin(["org","1"], ["org","9"]) holds for a tenant outside the fixture.'                         => $above,
        ];

        foreach ($failures as $message => $isWithin) {
            self::assertFails($message, self::harness(new SkewedTenantTree(isWithin: $isWithin))->testTenantTreeIsWithinHoldsForTheSubtreeAlone(...));
        }

        $elsewhere = static fn (Reference $tenant, Reference $ancestor): bool => $closure->isWithin($tenant, $ancestor) || $tenant->id === 'elsewhere';

        self::assertFails(
            'isWithin(["org","elsewhere"], ["org","1"]) holds for a tenant outside the fixture.',
            self::harness(new SkewedTenantTree(isWithin: $elsewhere), outsider: new Reference('org', 'elsewhere'))->testTenantTreeIsWithinHoldsForTheSubtreeAlone(...),
        );
    }

    /**
     * A subtree that leaves the tenant itself out fails, naming it missing; one
     * selecting integers is read as their strings, naming the pair extra.
     *
     * @return void
     */
    public function testTheKitFailsASubtreeWithTheWrongPairs(): void
    {
        $rootless = new SkewedTenantTree(subtree: static fn (Reference $tenant): Builder => self::closureSubtree($tenant)->where('depth', '>', 0));
        $integers = new SkewedTenantTree(subtree: static fn (): Builder => DB::query()->selectRaw('7 as tenant_type, 5 as tenant_id'));

        self::assertFails('The subtree of ["org","1"] is missing ["org","1"] and has nothing extra.', self::harness($rootless)->testTenantTreeSubtreeSelectsTheTypedSubtree(...));
        self::assertFails(
            'The subtree of ["org","1"] is missing ["account","3"], ["org","1"], ["team","1"], ["team","2"], ["team","7"] and has ["7","5"] extra.',
            self::harness($integers)->testTenantTreeSubtreeSelectsTheTypedSubtree(...),
        );
    }

    /**
     * A subtree whose rows lack a type or a key, or hold none, fails, since its
     * tenants cannot be told apart.
     *
     * @return void
     */
    public function testTheKitFailsUntypedRows(): void
    {
        $subtrees = [
            static fn (Reference $tenant): Builder => self::closureSubtree($tenant)->select(['descendant_id as tenant_id']),
            static fn (Reference $tenant): Builder => self::closureSubtree($tenant)->select(['descendant_type as tenant_type']),
            static fn (Reference $tenant): Builder => self::closureSubtree($tenant)->selectRaw('null as tenant_type')->addSelect('descendant_id as tenant_id'),
        ];

        foreach ($subtrees as $subtree) {
            self::assertStringContainsString(
                'The subtree of ["org","1"] returns a row without both a tenant_type and a tenant_id: it must select both, typed, for every tenant, never an id alone.',
                self::failure(self::harness(new SkewedTenantTree(subtree: $subtree))->testTenantTreeSubtreeSelectsTheTypedSubtree(...)),
            );
        }
    }

    /**
     * A subtree that is no query fails, naming what it is; one on another
     * connection than the one named fails, as does one on a connection with no
     * name; by default, the connection is the package's, as
     * `authorization.connection` names it.
     *
     * @return void
     */
    public function testTheKitFailsASubtreeThatIsNoQueryOnTheConnection(): void
    {
        $query = new class implements Builder {};

        self::assertFails(
            'The subtree of ["org","1"] is a ' . $query::class . ', not a query the package can run or nest.',
            self::harness(new SkewedTenantTree(subtree: static fn (): Builder => $query))->testTenantTreeSubtreeSelectsTheTypedSubtree(...),
        );

        self::assertFails(
            'The subtree of ["org","1"] is not a query on the connection \'elsewhere\', where it is nested.',
            self::harness(new ClosureTenantTree, 'elsewhere')->testTenantTreeSubtreeSelectsTheTypedSubtree(...),
        );

        $nameless = new QueryBuilder(self::createStub(ConnectionInterface::class), DB::connection()->getQueryGrammar(), new Processor);

        self::assertFails(
            'The subtree of ["org","1"] is not a query on the connection \'' . DB::getDefaultConnection() . '\'',
            self::harness(new SkewedTenantTree(subtree: static fn (): Builder => $nameless), null)->testTenantTreeSubtreeSelectsTheTypedSubtree(...),
        );

        config()->set('database.connections.tenants', config('database.connections.' . DB::getDefaultConnection()));
        config()->set('authorization.connection', 'tenants');

        $flat = [[new Reference('stub_tenant', '1'), null]];

        (new TenantTreeContractHarness(new FlatTenantTree, $flat))->testTenantTreeSubtreeSelectsTheTypedSubtree();

        self::assertFails(
            'The subtree of ["stub_tenant","1"] is not a query on the connection \'tenants\'',
            (new TenantTreeContractHarness(new ClosureTenantTree, $flat))->testTenantTreeSubtreeSelectsTheTypedSubtree(...),
        );
    }

    /**
     * A subtree that reads the tenant scope fails, naming the scope.
     *
     * @return void
     */
    public function testTheKitFailsASubtreeFollowingTheTenantScope(): void
    {
        $scoped = new SkewedTenantTree(subtree: static fn (Reference $tenant): Builder => self::closureSubtree($tenant)
            ->when(TenantScope::currentTenant() !== null, static fn (QueryBuilder $query): QueryBuilder => $query->whereRaw('1 = 0')));

        self::harness($scoped)->testTenantTreeSubtreeSelectsTheTypedSubtree();

        self::assertFails(
            'In the tenant scope of ["org","9"], the subtree of ["org","1"] is missing ["account","3"], ["org","1"], ["team","1"], ["team","2"], ["team","7"] '
            . 'and has nothing extra.',
            self::harness($scoped)->testTenantTreeSubtreeIgnoresTheTenantScope(...),
        );
    }

    /**
     * The tenant outside the fixture is of the first node's type, and keyed as
     * the fixture's tenants are, so the tree's storage can hold it: the largest
     * integer plus one when every key is digits, else `outside`, with a `-`
     * added until no tenant of the fixture is keyed so.
     *
     * @return void
     */
    public function testTheTenantOutsideTheFixtureIsKeyedAsItsTenantsAre(): void
    {
        $outsiders = [
            '["org","11"]'        => [['org', '9'], ['team', '10']],
            '["team","outside"]'  => [['team', '1'], ['org', 'a']],
            '["org","outside"]'   => [['org', '0b5e9c1e-8a51-4c1b-9f3e-2d1f4a6b7c80'], ['team', '7']],
            '["org","outside--"]' => [['org', 'outside'], ['team', 'outside-']],
        ];

        foreach ($outsiders as $expected => $tenants) {
            $nodes    = \array_map(static fn (array $tenant): array => [new Reference(...$tenant), null], $tenants);
            $outsider = (new TenantTreeContractHarness(new ClosureTenantTree, $nodes))->outsideTenant();

            self::assertSame($expected, \json_encode([$outsider->type, $outsider->id], \JSON_THROW_ON_ERROR));
        }
    }

    /**
     * The kit's three hooks are protected and open, so a test case overrides
     * them and reaches the kit's own through an alias, as the harness does.
     *
     * @return void
     */
    public function testTheKitsHooksAreOpenToATestCase(): void
    {
        foreach (['tenantTreeConnection', 'hasMixedTenantTypes', 'tenantTreeOutsider'] as $hook) {
            $method = new \ReflectionMethod(TenantTreeContract::class, $hook);

            self::assertTrue($method->isProtected() && !$method->isFinal() && !$method->isStatic() && !$method->isAbstract(), $hook);
        }
    }

    /**
     * Return a harness for the tree over the fixture of clashing ids, claimed
     * as mixed, on the connection given, else the package's, with the tenant
     * outside the fixture given, else the kit's.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @param  false|string|null  $connection
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $outsider
     * @return \Tests\Fixtures\TenantTrees\TenantTreeContractHarness
     */
    private static function harness(TenantTree $tree, false|string|null $connection = false, ?Reference $outsider = null): TenantTreeContractHarness
    {
        return new TenantTreeContractHarness($tree, ClashingTenants::nodes(), $connection, true, $outsider);
    }

    /**
     * Return the subtree of the tenant in the closure table, as the closure
     * tree writes it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Database\Query\Builder
     */
    private static function closureSubtree(Reference $tenant): QueryBuilder
    {
        return DB::table(ClosureTenantTree::TABLE)
            ->select(['descendant_type as tenant_type', 'descendant_id as tenant_id'])
            ->where('ancestor_type', $tenant->type)
            ->where('ancestor_id', $tenant->id);
    }

    /**
     * Run every check of the kit on the harness.
     *
     * @param  \Tests\Fixtures\TenantTrees\TenantTreeContractHarness  $harness
     * @return void
     */
    private static function check(TenantTreeContractHarness $harness): void
    {
        $harness->testTenantTreeFixtureIsATree();
        $harness->testTenantTreeAncestorsAreTheParentChain();
        $harness->testTenantTreeIsWithinHoldsForTheSubtreeAlone();
        $harness->testTenantTreeSubtreeSelectsTheTypedSubtree();
        $harness->testTenantTreeSubtreeNestsInAQuery();
        $harness->testTenantTreeSubtreeIgnoresTheTenantScope();
    }

    /**
     * Assert the check fails with a message holding the one given.
     *
     * @param  string  $message
     * @param  \Closure(): void  $check
     * @return void
     */
    private static function assertFails(string $message, \Closure $check): void
    {
        self::assertStringContainsString($message, self::failure($check));
    }

    /**
     * Return the message the check fails with, failing the test if it passes.
     *
     * @param  \Closure(): void  $check
     * @return string
     */
    private static function failure(\Closure $check): string
    {
        try {
            $check();
        } catch (AssertionFailedError $failure) {
            return $failure->getMessage();
        }

        self::fail('The kit passed a tree or fixture that breaks the contract.');
    }
}
