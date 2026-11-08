<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantPresence;
use SineMacula\Laravel\Authorization\Enums\GrantScopeStatus;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\TestCase;

/**
 * Query budget of the grant scope query and the principal presence helper
 * (AUTHZ-14.2, AUTHZ-13.8): each reads the grants in one query, with the
 * tenant's subtree nested in it, so the count is the same for one grant as for
 * thirty, and for a tenant two levels down as for one eight levels down.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantScopeQuery::class)]
final class GrantScopeQueryBudgetTest extends TestCase
{
    /** @var int How deep the deep chain of tenants goes. */
    private const int DEPTH = 8;

    /**
     * The scope query costs the same queries for one grant as for thirty, on
     * the identity and two principals, and whatever the tenant's depth.
     *
     * @return void
     */
    public function testTheScopeQueryCostIsIndependentOfGrantsAndDepth(): void
    {
        $this->chain();

        $few  = self::reference('few');
        $many = self::reference('many');

        $shallow = new Reference('tenant', 'level-1');
        $deep    = new Reference('tenant', 'level-' . self::DEPTH);

        $baseline = $this->queriesOf(static fn (): GrantScopeStatus => self::scopes()->forIdentity($few, $shallow));

        self::assertSame([GrantScopeStatus::WITHIN], $baseline['answers']);
        self::assertCount(1, $baseline['queries']);

        foreach ([[$many, $shallow], [$few, $deep], [$many, $deep]] as [$identity, $tenant]) {
            $measured = $this->queriesOf(static fn (): GrantScopeStatus => self::scopes()->forIdentity($identity, $tenant));

            self::assertCount(\count($baseline['queries']), $measured['queries'], "The scope query cost other queries:\n" . \implode("\n", $measured['queries']));
        }
    }

    /**
     * The presence helper costs the same queries for one grant as for thirty,
     * and whatever the tenant's depth: the tree's one read of the ancestors,
     * and the one read of the grants.
     *
     * @return void
     */
    public function testThePresenceHelperCostIsIndependentOfGrantsAndDepth(): void
    {
        $this->chain();

        $few  = new Subject(StubIdentity::query()->findOrFail('few-principal-0'), StubIdentity::query()->findOrFail('few'));
        $many = new Subject(StubIdentity::query()->findOrFail('many-principal-0'), StubIdentity::query()->findOrFail('many'));

        $shallow = new Reference('tenant', 'level-1');
        $deep    = new Reference('tenant', 'level-' . self::DEPTH);

        $baseline = $this->queriesOf(static fn (): GrantPresence => self::scopes()->hasGrantIn($few, $shallow));

        self::assertSame([GrantPresence::PRESENT], $baseline['answers']);
        self::assertCount(2, $baseline['queries']);

        foreach ([[$many, $shallow], [$few, $deep], [$many, $deep]] as [$subject, $tenant]) {
            $measured = $this->queriesOf(static fn (): GrantPresence => self::scopes()->hasGrantIn($subject, $tenant));

            self::assertCount(\count($baseline['queries']), $measured['queries'], "The presence helper cost other queries:\n" . \implode("\n", $measured['queries']));
        }
    }

    /**
     * Put a chain of tenants, each below the last, in the closure-table tree,
     * bind it, and give two identities, with two principals each, grants rooted
     * at the top of the chain: one of each kind for each grantee, or ten.
     *
     * @return void
     */
    private function chain(): void
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        $parent = null;

        for ($level = 1; $level <= self::DEPTH; $level++) {
            $tenant = new Reference('tenant', 'level-' . $level);

            ClosureTenantTree::add($tenant, $parent);

            $parent = $tenant;
        }

        $principals = [];

        foreach (['few' => 1, 'many' => 10] as $name => $count) {
            $grantees = [StubIdentity::create(['id' => $name]), StubIdentity::create(['id' => $name . '-principal-0']), StubIdentity::create(['id' => $name . '-principal-1'])];

            $principals[ListedIdentityDirectory::key(Reference::of($grantees[0]))] = [Reference::of($grantees[1]), Reference::of($grantees[2])];

            foreach ($grantees as $grantee) {
                self::grant($grantee, $count);
            }
        }

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory($principals));
    }

    /**
     * Grant the grantee the given number of roles, permissions and deny-only
     * policies, each at the top of the chain and reaching below it.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $grantee
     * @param  int  $count
     * @return void
     */
    private static function grant(StubIdentity $grantee, int $count): void
    {
        $top = new Reference('tenant', 'level-1');

        for ($index = 0; $index < $count; $index++) {
            /** @var string $key */
            $key  = $grantee->getKey();
            $name = $key . '-' . $index;

            $grantee->assignRole(Role::create(['name' => $name]), null, $top);
            $grantee->givePermission(Permission::create(['name' => $name . ':read']), null, $top);
            $grantee->attachPolicy(Policy::create(['name' => 'deny-' . $name, 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]]]]), null, $top);
        }
    }

    /**
     * Return the reference to the stub identity with the key.
     *
     * @param  string  $key
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function reference(string $key): Reference
    {
        return new Reference((new StubIdentity)->getMorphClass(), $key);
    }

    /**
     * Run the callback, and return its answer with the queries it ran.
     *
     * @template TAnswer
     *
     * @param  \Closure(): TAnswer  $callback
     * @return array{answers: list<TAnswer>, queries: list<string>}
     */
    private function queriesOf(\Closure $callback): array
    {
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $answer = $callback();

        $this->app?->make('events')->forget(QueryExecuted::class);

        return ['answers' => [$answer], 'queries' => $queries];
    }

    /**
     * Return the grant scope query the container builds.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantScopeQuery
     */
    private static function scopes(): GrantScopeQuery
    {
        /** @var \SineMacula\Laravel\Authorization\Services\GrantScopeQuery */
        return app(GrantScopeQuery::class);
    }
}
