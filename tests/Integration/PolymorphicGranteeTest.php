<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Cache\PrincipalCacheKey;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Database\GrantRelation;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\RequestState;
use Tests\Feature\Stubs\FoundationUser;
use Tests\Feature\Stubs\NumberedGrantee;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Feature\Stubs\StubSecondGrantee;
use Tests\TestCase;

/**
 * Integration tests covering polymorphic grantee support: two unrelated models
 * share the same role without model-class collisions, and a grant to one never
 * reaches another type with the same key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PrincipalCacheKey::class)]
#[CoversClass(GrantRelation::class)]
#[CoversTrait(HasRoles::class)]
final class PolymorphicGranteeTest extends TestCase
{
    /**
     * Two unrelated grantee models share a role and are granted the same
     * permission without any model-class collisions.
     *
     * @return void
     */
    public function testTwoDistinctGranteeModelsShareARole(): void
    {
        $role       = Role::create(['id' => 'f7e19d53-dd4e-49a2-8f1e-288453bffc75', 'name' => 'shared', 'guard' => 'web']);
        $permission = Permission::create(['id' => '9044baf5-429e-4b72-836a-73ca15cf8f8a', 'name' => 'thing:do', 'guard' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $first  = StubGrantee::create(['id' => '3a7d2eb1-f646-4131-897c-8d0a1a6ecaad']);
        $second = StubSecondGrantee::create(['id' => 'eb79f1c6-3794-4840-8f3c-8a8421db18b8']);

        $first->assignRole('shared');
        $second->assignRole('shared');

        self::assertTrue(Authorization::for($first)->can('thing:do'));
        self::assertTrue(Authorization::for($second)->can('thing:do'));

        // Polymorphic types on the pivot remain distinct.
        self::assertSame(
            [StubGrantee::class, StubSecondGrantee::class],
            self::sortedTypes(),
        );
    }

    /**
     * A grant to user 5 never lets client 5 through, cold, or with only the
     * user's entries in the memo or the store.
     *
     * @return void
     */
    public function testAGrantNeverAllowsAnotherTypeWithTheSameKey(): void
    {
        // Two integer-keyed types; that they read one table is incidental.
        $user   = FoundationUser::query()->forceCreate(['id' => 5]);
        $client = NumberedGrantee::query()->findOrFail(5);

        Role::create(['name' => 'writer', 'guard' => 'web'])->givePermission(Permission::create(['name' => 'posts:create', 'guard' => 'web']));

        $user->assignRole('writer');
        $user->givePermission(Permission::create(['name' => 'posts:delete', 'guard' => 'web']));
        $user->attachPolicy(Policy::create([
            'name'     => 'publish',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:publish']]]],
        ]));

        self::assertSame([false, false, false], self::decisions($client), 'cold');

        $this->startRequest(flushStore: true);

        self::assertSame([true, true, true], self::decisions($user));
        self::assertSame([false, false, false], self::decisions($client), 'memo');

        $this->startRequest(flushStore: true);

        self::assertSame([true, true, true], self::decisions($user));

        $this->startRequest();

        DB::enableQueryLog();
        self::assertSame([true, true, true], self::decisions($user));
        self::assertSame([], DB::getQueryLog(), 'The user is decided from the store.');
        DB::disableQueryLog();

        $this->startRequest();

        self::assertSame([false, false, false], self::decisions($client), 'store');
    }

    /**
     * Back the resolution cache with a persistent store.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('authorization.cache.store', 'array');
    }

    /**
     * Start a request with an empty memo, and an empty store when asked.
     *
     * @param  bool  $flushStore
     * @return void
     */
    private function startRequest(bool $flushStore = false): void
    {
        if ($flushStore) {
            Cache::store('array')->clear();
        }

        RequestState::forget($this->container());
    }

    /**
     * Return whether the grantee may create, delete and publish posts.
     *
     * @param  object  $grantee
     * @return list<bool>
     */
    private static function decisions(object $grantee): array
    {
        return \array_map(static fn (string $action): bool => Authorization::for($grantee)->can($action), ['posts:create', 'posts:delete', 'posts:publish']);
    }

    /**
     * Return the distinct polymorphic types recorded on the role pivot.
     *
     * @return array<int, string>
     */
    private static function sortedTypes(): array
    {
        $types = DB::table('authorizable_roles')
            ->select('authorizable_type')
            ->distinct()
            ->pluck('authorizable_type')
            ->all();

        \sort($types);

        // @phpstan-ignore-next-line return.type, arrayValues.list
        return \array_values($types);
    }
}
