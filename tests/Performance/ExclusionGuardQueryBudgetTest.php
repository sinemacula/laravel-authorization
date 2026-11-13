<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionGuard;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleExclusionService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Query budget of separation of duties on a grant (AUTHZ-11.8, N136): a grant
 * no pair touches, of a role with no parent, costs one query more, whatever it
 * writes and whatever pairs are declared elsewhere, and a grant a pair touches
 * reads the report in a fixed number of queries, the same for two holders of
 * the pair's roles as for forty.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExclusionGuard::class)]
final class ExclusionGuardQueryBudgetTest extends TestCase
{
    /**
     * A grant of a role no pair touches costs the same queries before and after
     * a pair of other roles is declared, one of them the pairs' read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantNoPairTouchesReadsThePairsOnce(): void
    {
        $idle = Role::query()->create(['name' => 'idle']);

        $before = self::queriesOf(static fn () => self::grants()->grantRole(StubIdentity::query()->create(['id' => 'first']), $idle));

        self::exclusions()->declare(Role::query()->create(['name' => 'clerk']), Role::query()->create(['name' => 'auditor']));

        $after = self::queriesOf(static fn () => self::grants()->grantRole(StubIdentity::query()->create(['id' => 'second']), $idle));

        self::assertCount(\count($before), $after, "The grant cost other queries:\n" . \implode("\n", $after));
        self::assertCount(1, self::naming('role_exclusions', $after));
    }

    /**
     * Whatever a grant of a role no pair touches writes, a new row, a later or
     * an earlier expiry or a re-armed grant, it costs the grant table's own
     * queries and the walk up from the role, first; a permission grant costs
     * its table's own queries and the permission's lookup, and reads no role.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWriteNoPairTouchesCostsOneQueryMore(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        self::exclusions()->declare(Role::query()->create(['name' => 'clerk']), Role::query()->create(['name' => 'auditor']));

        $idle = Role::query()->create(['name' => 'idle']);
        $user = StubIdentity::query()->create(['id' => 'user']);

        // The grant table's own queries: an insert, then, for a held row, its
        // locked read and the rewrite.
        $writes = [
            'new'      => [Carbon::now()->addDay(), 1],
            'later'    => [Carbon::now()->addWeek(), 3],
            'earlier'  => [Carbon::now()->addHour(), 3],
            're-armed' => [Carbon::now()->addDay(), 3],
        ];

        foreach ($writes as $name => [$expiresAt, $cost]) {
            if ($name === 're-armed') {
                DB::table('authorizable_roles')->update(['expires_at' => Carbon::now()->subDay()]);
            }

            $queries = self::queriesOf(static fn () => self::grants()->grantRole($user, $idle, $expiresAt));

            self::assertCount($cost + 1, $queries, "The {$name} grant cost other queries:\n" . \implode("\n", $queries));
            self::assertCount($cost, self::naming('authorizable_roles', $queries), $name);
            self::assertStringContainsString('role_exclusions', $queries[0], $name);
        }

        Permission::query()->create(['name' => 'posts:edit']);

        foreach ([[Carbon::now()->addDay(), 1], [Carbon::now()->addWeek(), 3]] as [$expiresAt, $cost]) {
            $queries = self::queriesOf(static fn () => self::grants()->grantPermission($user, 'posts:edit', $expiresAt));

            self::assertCount($cost + 1, $queries, "The permission grant cost other queries:\n" . \implode("\n", $queries));
            self::assertCount($cost, self::naming('authorizable_permissions', $queries));
            self::assertSame([], self::naming('role', $queries));
        }

        Carbon::setTestNow();
    }

    /**
     * A grant of a role of a declared pair costs the same queries for two
     * holders of the pair's roles as for forty, at the platform and in tenants
     * of their own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantAPairTouchesCostsTheSameWhateverHoldsItsRoles(): void
    {
        $clerk   = Role::query()->create(['name' => 'clerk']);
        $auditor = Role::query()->create(['name' => 'auditor']);

        self::exclusions()->declare($clerk, $auditor);
        self::holders(1, 2, $clerk);

        $few = self::queriesOf(static fn () => self::grants()->grantRole(StubIdentity::query()->create(['id' => 'few']), $auditor, tenant: new Reference('stub_tenant', 't1')));

        self::holders(3, 40, $clerk);

        $many = self::queriesOf(static fn () => self::grants()->grantRole(StubIdentity::query()->create(['id' => 'many']), $auditor, tenant: new Reference('stub_tenant', 't1')));

        self::assertCount(\count($few), $many, "The grant cost other queries:\n" . \implode("\n", $many));
    }

    /**
     * Grant the role to the holders numbered from the first to the last, the
     * odd ones at the platform and the even ones in tenants of their own.
     *
     * @param  int  $first
     * @param  int  $last
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \Throwable
     */
    private static function holders(int $first, int $last, Role $role): void
    {
        for ($index = $first; $index <= $last; $index++) {
            $holder = StubIdentity::query()->create(['id' => "holder-{$index}"]);
            $tenant = $index % 2 === 0 ? new Reference('stub_tenant', "h{$index}") : null;

            self::grants()->grantRole($holder, $role, tenant: $tenant);
        }
    }

    /**
     * Return the queries the call ran on the package's connection.
     *
     * @param  \Closure(): mixed  $call
     * @return list<string>
     */
    private static function queriesOf(\Closure $call): array
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $call();

        $queries = \array_column(DB::getQueryLog(), 'query');

        DB::disableQueryLog();

        return $queries;
    }

    /**
     * Return the queries naming the text.
     *
     * @param  string  $text
     * @param  list<string>  $queries
     * @return list<string>
     */
    private static function naming(string $text, array $queries): array
    {
        return \array_values(\array_filter($queries, static fn (string $sql): bool => \str_contains($sql, $text)));
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
     * Return the role exclusion service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleExclusionService
     */
    private static function exclusions(): RoleExclusionService
    {
        return app(RoleExclusionService::class);
    }
}
