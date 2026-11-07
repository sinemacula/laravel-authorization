<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\AffectedHolders;
use SineMacula\Laravel\Authorization\Administration\Impact;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Query budget of the impact check (BL-65 part 3): the holders a change to a
 * shared definition reaches are read set by set, and weighed together, so
 * adding a permission to a role, renaming a permission and rewriting a policy
 * each run the same number of queries for thirty holders as for three.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AffectedHolders::class)]
#[CoversClass(Impact::class)]
final class AdministrationImpactQueryBudgetTest extends TestCase
{
    /**
     * Each change reads as much with thirty holders, some through a role below
     * the role changed, as with three.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheImpactCheckCostsTheSameWhateverTheHolders(): void
    {
        $actor = self::administrator();
        $calls = [
            'adding a permission to a role' => static function (string $batch, int $holders) use ($actor): \Closure {
                $role = self::heldRole($batch, $holders);

                return static fn (): mixed => self::roles()->grantPermission($role, 'posts:edit', actor: $actor);
            },
            'renaming a permission' => static function (string $batch, int $holders) use ($actor): \Closure {
                $permission = Permission::query()->create(['name' => "posts:{$batch}"]);

                foreach (self::users($batch, $holders) as $user) {
                    self::grants()->grantPermission($user, $permission);
                }

                return static fn (): mixed => self::permissions()->rename($permission, "posts:{$batch}-renamed", $actor);
            },
            'rewriting a policy' => static function (string $batch, int $holders) use ($actor): \Closure {
                $policy = Policy::create(['name' => "policy-{$batch}", 'document' => ['statements' => []]]);

                foreach (self::users($batch, $holders) as $user) {
                    self::grants()->attachPolicy($user, $policy);
                }

                return static fn (): mixed => self::policies()->rewrite($policy, ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]], $actor);
            },
        ];

        foreach ($calls as $name => $call) {
            $batch = \str_replace(' ', '-', $name);
            $few   = self::queriesOf($call("few-{$batch}", 3));
            $many  = self::queriesOf($call("many-{$batch}", 30));

            self::assertSame($few, $many, "{$name} read more for more holders.");
        }
    }

    /**
     * Return a role held by the number of new identities, half of them through
     * a role below it.
     *
     * @param  string  $batch
     * @param  int  $holders
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    private static function heldRole(string $batch, int $holders): Role
    {
        $role  = Role::create(['name' => "role-{$batch}"]);
        $below = Role::create(['name' => "below-{$batch}", 'parent_id' => $role->id]);

        foreach (self::users($batch, $holders) as $index => $user) {
            self::grants()->grantRole($user, $index % 2 === 0 ? $role : $below);
        }

        return $role;
    }

    /**
     * Create the number of new identities, each named from the batch.
     *
     * @param  string  $batch
     * @param  int  $count
     * @return list<\Tests\Feature\Stubs\StubIdentity>
     */
    private static function users(string $batch, int $count): array
    {
        $users = [];

        for ($index = 0; $index < $count; $index++) {
            $users[] = StubIdentity::create(['id' => \md5($batch) . '-' . $index]);
        }

        return $users;
    }

    /**
     * Count the queries the call makes.
     *
     * @param  \Closure(): mixed  $call
     * @return int
     */
    private static function queriesOf(\Closure $call): int
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $call();

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

        foreach (['authorization:*', 'posts:*', 'posts:edit', 'posts:read'] as $name) {
            Permission::query()->firstOrCreate(['name' => $name]);
        }

        self::grants()->grantPermission($admin, 'authorization:*');
        self::grants()->grantPermission($admin, 'posts:*');

        return ActingContext::for($admin);
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

    /**
     * Return the permission service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\PermissionService
     */
    private static function permissions(): PermissionService
    {
        return app(PermissionService::class);
    }

    /**
     * Return the policy service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\PolicyService
     */
    private static function policies(): PolicyService
    {
        return app(PolicyService::class);
    }
}
