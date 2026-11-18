<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use Tests\Feature\Stubs\StubGrantee;
use Tests\TestCase;

/**
 * Query budget of trusted bulk grant changes: revoking everything a grantee
 * holds reads and writes each grant table at once, and a sync reads what it
 * drops at once, so neither costs more as the grantee's rows grow.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantService::class)]
final class GrantServiceQueryBudgetTest extends TestCase
{
    /**
     * Revoking everything costs as many queries for a grantee holding two of
     * each kind of grant as for one holding twelve.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingEverythingCostsTheSameWhateverIsHeld(): void
    {
        $few  = self::holding('few', 2);
        $many = self::holding('many', 12);

        self::assertSame(
            self::queriesOf(static fn (): int => self::grants()->revokeAll($few)),
            self::queriesOf(static fn (): int => self::grants()->revokeAll($many)),
        );

        $tables = ['authorizable_roles', 'authorizable_permissions', 'authorizable_policies'];

        self::assertSame([0, 0, 0], \array_map(static fn (string $table): int => DB::table($table)->count(), $tables));
    }

    /**
     * A sync of the same two roles costs as many queries whether it drops two
     * held roles or twelve.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncCostsTheSameWhateverItDrops(): void
    {
        $few  = self::holding('few', 2);
        $many = self::holding('many', 12);

        Role::query()->create(['name' => 'kept-a']);
        Role::query()->create(['name' => 'kept-b']);

        $sync = static fn (StubGrantee $user): \Closure => static fn (): mixed => self::grants()->syncRoles($user, ['kept-a', 'kept-b']);

        self::assertSame(self::queriesOf($sync($few)), self::queriesOf($sync($many)));
        self::assertSame(4, DB::table('authorizable_roles')->count());
    }

    /**
     * Return a new grantee with the id, holding the number of roles,
     * permissions and policies, each platform-wide.
     *
     * @param  string  $id
     * @param  int  $count
     * @return \Tests\Feature\Stubs\StubGrantee
     *
     * @throws \Throwable
     */
    private static function holding(string $id, int $count): StubGrantee
    {
        $user = StubGrantee::query()->create(['id' => $id]);

        for ($index = 0; $index < $count; $index++) {
            self::grants()->grantRole($user, Role::query()->firstOrCreate(['name' => "role-{$index}"]));
            self::grants()->grantPermission($user, Permission::query()->firstOrCreate(['name' => "posts:edit-{$index}"]));
            self::grants()->attachPolicy($user, Policy::query()->firstOrCreate(['name' => "policy-{$index}"], ['document' => ['statements' => []]]));
        }

        return $user;
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
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        return app(GrantService::class);
    }
}
