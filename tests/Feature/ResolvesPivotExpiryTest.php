<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\ResolvesPivotExpiry;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the read of an existing grant that the grant methods use to
 * tell whether a re-grant changes the expiry, and for the lookups a revocation
 * or synchronisation by name works from: every row that answers a name under
 * the identity's guard, and which of them the identity holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(ResolvesPivotExpiry::class)]
final class ResolvesPivotExpiryTest extends TestCase
{
    /** @var string The identity whose grants are read. */
    private const string IDENTITY = '5b0c2e1a-7f3d-4a9b-8c6e-1d2f3a4b5c6d';

    /** @var string Another identity, whose grants must not be read. */
    private const string OTHER_IDENTITY = '9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b';

    /**
     * No row for the identity and target reads as no grant.
     *
     * @return void
     */
    public function testMissingGrantReadsAsAbsent(): void
    {
        $role = Role::query()->create(['name' => 'editor']);

        self::assertSame(['exists' => false, 'expires_at' => null], $this->read(self::identity(self::IDENTITY), $role));
    }

    /**
     * A stored grant reads back with its expiry.
     *
     * @return void
     */
    public function testExistingGrantReadsBackWithItsExpiry(): void
    {
        $identity = self::identity(self::IDENTITY);
        $role     = Role::query()->create(['name' => 'editor']);

        $this->grant($identity, $role, '2030-01-02 03:04:05');

        $read = $this->read($identity, $role);

        self::assertTrue($read['exists']);
        self::assertSame('2030-01-02 03:04:05', $read['expires_at']?->format('Y-m-d H:i:s'));
    }

    /**
     * A stored grant without an expiry reads back as existing and forever.
     *
     * @return void
     */
    public function testExistingGrantWithoutExpiryReadsBackAsForever(): void
    {
        $identity = self::identity(self::IDENTITY);
        $role     = Role::query()->create(['name' => 'editor']);

        $this->grant($identity, $role, null);

        self::assertSame(['exists' => true, 'expires_at' => null], $this->read($identity, $role));
    }

    /**
     * Only the identity's own grant of the named target is read: another
     * identity's grant of it, another target's grant and a grant to another
     * grantee type with the same id are not.
     *
     * @return void
     */
    public function testOnlyTheIdentitysGrantOfTheTargetIsRead(): void
    {
        $identity = self::identity(self::IDENTITY);
        $role     = Role::query()->create(['name' => 'editor']);
        $other    = Role::query()->create(['name' => 'author']);

        $this->grant(self::identity(self::OTHER_IDENTITY), $role, null);
        $this->grant($identity, $other, null);

        DB::table('authorizable_roles')->insert([
            'role_id'           => $role->id,
            'authorizable_type' => 'another_type',
            'authorizable_id'   => self::IDENTITY,
        ]);

        self::assertSame(['exists' => false, 'expires_at' => null], $this->read($identity, $role));
    }

    /**
     * The stored expiry is read as UTC, whatever the application's zone.
     *
     * @return void
     */
    public function testExistingGrantExpiryIsReadAsUtc(): void
    {
        $identity = self::identity(self::IDENTITY);
        $role     = Role::query()->create(['name' => 'editor']);

        $this->grant($identity, $role, '2030-01-02 03:04:05');

        $zone = \date_default_timezone_get();

        \date_default_timezone_set('Asia/Tokyo');

        try {
            $read = $this->read($identity, $role);
        } finally {
            \date_default_timezone_set($zone);
        }

        self::assertSame(Carbon::parse('2030-01-02 03:04:05', 'UTC')->getTimestamp(), $read['expires_at']?->getTimestamp());
    }

    /**
     * Only the given models the identity holds are returned, in the order
     * given, an expired grant included and another identity's grant not.
     *
     * @return void
     */
    public function testHeldAmongReturnsTheHeldModelsInTheOrderGiven(): void
    {
        $identity = self::identity(self::IDENTITY);
        $first    = Role::query()->create(['name' => 'first']);
        $second   = Role::query()->create(['name' => 'second']);
        $third    = Role::query()->create(['name' => 'third']);

        $this->grant($identity, $third, null);
        $this->grant($identity, $first, '2000-01-01 00:00:00');
        $this->grant(self::identity(self::OTHER_IDENTITY), $second, null);

        $held = self::held($identity->roles()->newPivotQuery(), 'role_id', [$first, $second, $third]);

        self::assertSame([$first->id, $third->id], \array_map(static fn (Model $model): mixed => $model->getKey(), $held));
        self::assertSame([], self::held($identity->roles()->newPivotQuery(), 'role_id', []));
    }

    /**
     * The rows that answer a name are those for the identity's own guard and
     * the guard-agnostic ones, ranked guard-specific first.
     *
     * @return void
     */
    public function testAllNamedUsesTheIdentitysGuard(): void
    {
        $rows = $this->rolesForEveryGuard();

        $identity = new class {
            /**
             * Return the guard the identity authenticates under.
             *
             * @return string
             */
            public function getAuthorizationGuard(): string
            {
                return 'api';
            }
        };

        self::assertSame([$rows['api'], $rows['none']], $this->namedKeys($identity));
    }

    /**
     * An identity that names no guard uses the configured default guard.
     *
     * @return void
     */
    public function testAllNamedUsesTheDefaultGuardWhenTheIdentityNamesNone(): void
    {
        $rows = $this->rolesForEveryGuard();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(Repository::class);

        $config->set('authorization.defaults.guard', 'admin');

        self::assertSame([$rows['admin'], $rows['none']], $this->namedKeys(self::identity(self::IDENTITY)));
    }

    /**
     * Create a stub identity with the given id.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function identity(string $id): StubIdentity
    {
        return StubIdentity::query()->create(['id' => $id]);
    }

    /**
     * Write a grant of the role to the identity with the given expiry.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  string|null  $expiresAt
     * @return void
     */
    private function grant(StubIdentity $identity, Role $role, ?string $expiresAt): void
    {
        DB::table('authorizable_roles')->insert([
            'role_id'           => $role->id,
            'authorizable_type' => $identity->getMorphClass(),
            'authorizable_id'   => $identity->id,
            'expires_at'        => $expiresAt,
        ]);
    }

    /**
     * Create a role named `editor` for each of three guards and one that is
     * guard-agnostic, keyed by guard.
     *
     * @return array<string, string>
     */
    private function rolesForEveryGuard(): array
    {
        $keys = [];

        foreach (['web' => 'web', 'api' => 'api', 'admin' => 'admin', 'none' => null] as $key => $guard) {
            $keys[$key] = Role::query()->create(['name' => 'editor', 'guard' => $guard])->id;
        }

        return $keys;
    }

    /**
     * Return the keys of every role named `editor` for the identity's guard, in
     * the order the lookup ranks them.
     *
     * @param  object  $identity
     * @return list<mixed>
     */
    private function namedKeys(object $identity): array
    {
        return \array_map(static fn (Model $model): mixed => $model->getKey(), self::named($identity, Role::class, 'editor'));
    }

    /**
     * Return the models among the given ones the pivot query holds, through the
     * trait.
     *
     * @param  \Illuminate\Database\Query\Builder  $pivot
     * @param  string  $column
     * @param  list<\Illuminate\Database\Eloquent\Model>  $models
     * @return list<\Illuminate\Database\Eloquent\Model>
     */
    private static function held(Builder $pivot, string $column, array $models): array
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * Return the models among the given ones the pivot query holds.
             *
             * @param  \Illuminate\Database\Query\Builder  $pivot
             * @param  string  $column
             * @param  list<\Illuminate\Database\Eloquent\Model>  $models
             * @return list<\Illuminate\Database\Eloquent\Model>
             */
            public function held(Builder $pivot, string $column, array $models): array
            {
                return self::authorizationHeldAmong($pivot, $column, $models);
            }
        };

        return $probe->held($pivot, $column, $models);
    }

    /**
     * Return every row of the class that answers the name under the identity's
     * guard, through the trait.
     *
     * @param  object  $identity
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @param  string  $name
     * @return list<\Illuminate\Database\Eloquent\Model>
     */
    private static function named(object $identity, string $class, string $name): array
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * Return every row of the class that answers the name.
             *
             * @param  object  $identity
             * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
             * @param  string  $name
             * @return list<\Illuminate\Database\Eloquent\Model>
             */
            public function named(object $identity, string $class, string $name): array
            {
                return self::authorizationAllNamed($identity, $class, $name);
            }
        };

        return $probe->named($identity, $class, $name);
    }

    /**
     * Read the identity's grant of the role through the trait.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return array{exists: bool, expires_at: \DateTimeInterface|null}
     */
    private function read(StubIdentity $identity, Role $role): array
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * Read the grant.
             *
             * @param  \Illuminate\Database\Eloquent\Model&\Tests\Feature\Stubs\StubIdentity  $identity
             * @param  string  $roleId
             * @return array{exists: bool, expires_at: \DateTimeInterface|null}
             */
            public function read(Model $identity, string $roleId): array
            {
                return self::authorizationReadGrantPivot($identity, $identity->roles()->newPivotStatement(), 'role_id', $roleId);
            }
        };

        return $probe->read($identity, $role->id);
    }
}
