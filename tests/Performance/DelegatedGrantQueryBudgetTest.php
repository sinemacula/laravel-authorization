<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\GrantReach;
use SineMacula\Laravel\Authorization\Administration\PossessionLimits;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Query budget of a delegated direct grant (BL-65 part 2): what the possession
 * route reads to prove the actor holds what it grants is read a table at a
 * time, the grant's reach in the query, and every policy found in one more
 * query, so a delegated grant, or a sync's additions, runs the same number of
 * queries however many resource policies and guardrails other tenants and other
 * records have.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PossessionLimits::class)]
#[CoversClass(GrantReach::class)]
final class DelegatedGrantQueryBudgetTest extends TestCase
{
    /** @var int How many unrelated resource policies and guardrails are stored. */
    private const int UNRELATED = 30;

    /**
     * A delegated grant in a tenant, platform-wide, and a sync's additions,
     * each run as many queries with thirty unrelated resource policies and
     * guardrails as with none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedGrantCostsTheSameWhateverElseIsStored(): void
    {
        $actor  = self::administrator();
        $tenant = new Reference('tenant', 'a');
        $calls  = [
            'a grant in a tenant' => static fn (StubIdentity $user): mixed => self::grants()->grantPermission($user, 'posts:edit', actor: $actor, tenant: $tenant),
            'a platform grant'    => static fn (StubIdentity $user): mixed => self::grants()->grantPermission($user, 'posts:edit', actor: $actor),
            'a sync'              => static fn (StubIdentity $user): mixed => self::grants()->syncPermissions($user, ['posts:edit', 'posts:read'], actor: $actor, tenant: $tenant),
        ];

        foreach ($calls as $name => $call) {
            $call(self::user('warm-' . $name));

            $before = self::queriesOf($call, self::user('before-' . $name));

            self::storeUnrelated($name);

            self::assertSame($before, self::queriesOf($call, self::user('after-' . $name)), "{$name} read more once unrelated rows were stored.");
        }
    }

    /**
     * Store resource policies attached to records of other tenants, and
     * guardrails set on other tenants, none of which reaches the grants.
     *
     * @param  string  $batch
     * @return void
     */
    private static function storeUnrelated(string $batch): void
    {
        for ($index = 0; $index < self::UNRELATED; $index++) {
            $policy = Policy::create(['name' => "unrelated-{$batch}-{$index}", 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['billing:refund']]]]]);
            $tenant = ['tenant_type' => 'tenant', 'tenant_id' => "other-{$batch}-{$index}"];

            $row = ['policy_id' => $policy->id, ...$tenant, 'created_at' => now(), 'updated_at' => now()];

            DB::table('resource_policies')->insert([...$row, 'resource_type' => 'invoices', 'resource_id' => (string) $index, 'include_subtree' => true]);
            DB::table('guardrails')->insert($row);
        }
    }

    /**
     * Count the queries the call makes for the grantee.
     *
     * @param  \Closure(\Tests\Feature\Stubs\StubIdentity): mixed  $call
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return int
     */
    private static function queriesOf(\Closure $call, StubIdentity $user): int
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $call($user);

        $count = \count(DB::getQueryLog());

        DB::disableQueryLog();

        return $count;
    }

    /**
     * Return the acting context of an administrator holding every
     * administration action and `posts:*`, platform-wide, and the most senior
     * rank.
     *
     * @return \SineMacula\Laravel\Authorization\Administration\ActingContext
     *
     * @throws \Throwable
     */
    private static function administrator(): ActingContext
    {
        $admin = StubIdentity::create(['id' => 'admin']);

        self::grants()->grantRole($admin, Role::create(['name' => 'chief', 'rank' => 0]));

        foreach (['authorization:*', 'posts:*', 'posts:edit', 'posts:read', PackagePermissions::PERMISSION_GRANT] as $name) {
            Permission::query()->firstOrCreate(['name' => $name]);
        }

        self::grants()->grantPermission($admin, 'authorization:*');
        self::grants()->grantPermission($admin, 'posts:*');

        return ActingContext::for($admin);
    }

    /**
     * Return a new identity with the id.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function user(string $id): StubIdentity
    {
        return StubIdentity::create(['id' => $id]);
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
