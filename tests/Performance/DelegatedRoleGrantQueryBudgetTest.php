<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\Possession;
use SineMacula\Laravel\Authorization\Administration\RoleAuthority;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Query budget of a delegated role grant (BL-65 part 3): the whole authority a
 * role hands out is weighed in one pass, every permission it carries, and every
 * action a policy attached to it allows, decided together, so granting a role
 * that carries thirty permissions, or a policy allowing thirty actions, runs
 * the same number of queries as one that carries three, whether the actor holds
 * them or may grant them explicitly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RoleAuthority::class)]
#[CoversClass(Possession::class)]
final class DelegatedRoleGrantQueryBudgetTest extends TestCase
{
    /**
     * A role carrying thirty permissions, or a policy allowing thirty actions,
     * costs as many queries to grant as one carrying three, held or explicitly
     * grantable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleGrantCostsTheSameWhateverTheRoleCarries(): void
    {
        $actor = self::administrator();
        $kinds = [
            'held permissions'        => static fn (string $batch, int $count): Role => self::carrying($batch, 'posts', $count),
            'grantable permissions'   => static fn (string $batch, int $count): Role => self::carrying($batch, 'billing', $count),
            'a policy of held rights' => static fn (string $batch, int $count): Role => self::allowing($batch, 'posts', $count),
        ];

        foreach ($kinds as $name => $role) {
            $batch = \str_replace(' ', '-', $name);
            $few   = self::queriesOf($actor, $role("few-{$batch}", 3), "few-{$batch}");
            $many  = self::queriesOf($actor, $role("many-{$batch}", 30), "many-{$batch}");

            self::assertSame($few, $many, "Granting a role of {$name} read more for more of them.");
        }
    }

    /**
     * Return a new role carrying the number of permissions, each named under
     * the prefix.
     *
     * @param  string  $batch
     * @param  string  $prefix
     * @param  int  $count
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    private static function carrying(string $batch, string $prefix, int $count): Role
    {
        $role = Role::create(['name' => "role-{$batch}", 'rank' => 5]);

        for ($index = 0; $index < $count; $index++) {
            self::roles()->grantPermission($role, Permission::query()->create(['name' => "{$prefix}:{$batch}-{$index}"]));
        }

        return $role;
    }

    /**
     * Return a new role with an attached policy allowing the number of actions,
     * each named under the prefix, and carrying nothing else.
     *
     * @param  string  $batch
     * @param  string  $prefix
     * @param  int  $count
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    private static function allowing(string $batch, string $prefix, int $count): Role
    {
        $role    = Role::create(['name' => "role-{$batch}", 'rank' => 5]);
        $actions = \array_map(static fn (int $index): string => "{$prefix}:{$batch}-{$index}", \range(0, $count - 1));
        $policy  = Policy::create(['name' => "policy-{$batch}", 'document' => ['statements' => [['effect' => 'allow', 'actions' => $actions]]]]);

        self::grants()->attachPolicy($role, $policy);

        return $role;
    }

    /**
     * Count the queries a delegated grant of the role to a new identity makes.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  string  $batch
     * @return int
     *
     * @throws \Throwable
     */
    private static function queriesOf(ActingContext $actor, Role $role, string $batch): int
    {
        $user = StubIdentity::create(['id' => \md5($batch)]);

        DB::flushQueryLog();
        DB::enableQueryLog();

        self::grants()->grantRole($user, $role, actor: $actor);

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

        foreach (['authorization:*', 'posts:*'] as $name) {
            Permission::query()->firstOrCreate(['name' => $name]);

            self::grants()->grantPermission($admin, $name);
        }

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
}
