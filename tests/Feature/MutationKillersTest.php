<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Concerns\ResolvesPivotExpiry;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpiryChanged;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\NonTaggableCacheStore;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Mutation-killer feature tests targeting the `ResolvesPivotExpiry` helper, the
 * `ResolutionCache` TTL / key routing, and the authorizable-identity trait
 * branches whose semantic mutants escaped the initial mutation sweep.
 *
 * These tests assert exact values (counts, keys, time bounds) so subtle
 * mutations — `<` vs `<=`, `||` vs `&&`, off-by-one on integer literals, cast
 * removal — surface as failures rather than silently passing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(ResolutionCache::class)]
#[CoversClass(Statement::class)]
#[CoversClass(ConditionEvaluator::class)]
#[CoversClass(AuthorizationManager::class)]
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversTrait(HasPolicies::class)]
#[CoversTrait(ResolvesPivotExpiry::class)]
final class MutationKillersTest extends TestCase
{
    /**
     * `authorizationCollectModelIds` stringifies integer keys, drops empty
     * strings, and dedupes. The assertions pin all three behaviours so a
     * logical / cast / unique mutant breaks.
     *
     * @return void
     */
    public function testCollectModelIdsStringifiesAndDedupesAndDropsEmpty(): void
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @param  iterable<int, \Illuminate\Database\Eloquent\Model>  $models
             * @return array<string, mixed>
             */
            public function collect(iterable $models): array // @phpstan-ignore missingType.iterableValue
            {
                return self::authorizationCollectModelIds($models); // @phpstan-ignore return.type
            }
        };

        $collected = $probe->collect([
            $this->makeModelWithKey(42),
            $this->makeModelWithKey('alpha'),
            $this->makeModelWithKey('alpha'),
            $this->makeModelWithKey(''),
            $this->makeModelWithKey(new \stdClass),
        ]);

        // Integer 42 must be cast to string '42'; empties dropped;
        // duplicates squashed; non-string/non-int keys skipped.
        self::assertSame(['42', 'alpha'], $collected); // @phpstan-ignore staticMethod.impossibleType
    }

    /**
     * `authorizationCollectModelIds` returns an empty array when every model is
     * malformed — pins the foreach iteration against Foreach_ / break mutants.
     *
     * @return void
     */
    public function testCollectModelIdsReturnsEmptyForAllMalformedModels(): void
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @param  iterable<int, \Illuminate\Database\Eloquent\Model>  $models
             * @return array<string, mixed>
             */
            public function collect(iterable $models): array
            {
                return self::authorizationCollectModelIds($models); // @phpstan-ignore return.type
            }
        };

        $empty = new class extends Model {
            /**
             * @return mixed
             */
            #[\Override]
            public function getKey(): mixed
            {
                return '';
            }
        };

        $objectKeyedIdentity = new class extends Model {
            /**
             * @return mixed
             */
            #[\Override]
            public function getKey(): mixed
            {
                return new \stdClass;
            }
        };

        self::assertSame([], $probe->collect([$empty, $objectKeyedIdentity, $empty]));
    }

    /**
     * `authorizationNearestPivotExpirySeconds` returns the smallest positive
     * seconds-until-expiry across pivot rows. Pins the strict less-than
     * comparison against `<=` mutants.
     *
     * @return void
     */
    public function testNearestPivotExpirySelectsStrictlySmallerSeconds(): void
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @param  iterable<int, \Illuminate\Database\Eloquent\Model>  $related
             * @return int|null
             */
            public function nearest(iterable $related): ?int
            {
                return self::authorizationNearestPivotExpirySeconds($related);
            }
        };

        $now = Carbon::now();

        $mk = static function (int $seconds) use ($now): Model {
            $model             = new class extends Model {};
            $pivot             = new \stdClass;
            $pivot->expires_at = (clone $now)->addSeconds($seconds)->toDateTimeString();
            $model->setRelation('pivot', $pivot);

            return $model;
        };

        // Shape: 30s, 10s, 60s — the nearest is 10s.
        $models = [$mk(30), $mk(10), $mk(60)];

        $nearest = $probe->nearest($models);

        self::assertNotNull($nearest);
        // The exact value depends on test wall-clock; bound it.
        self::assertGreaterThanOrEqual(8, $nearest);
        self::assertLessThanOrEqual(10, $nearest);
    }

    /**
     * `authorizationNearestPivotExpirySeconds` returns null when no pivot row
     * carries a live expiry — pins the null-return against ReturnRemoval /
     * null-default mutants.
     *
     * @return void
     */
    public function testNearestPivotExpiryReturnsNullWhenNoLiveExpiries(): void
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @param  iterable<int, \Illuminate\Database\Eloquent\Model>  $related
             * @return int|null
             */
            public function nearest(iterable $related): ?int
            {
                return self::authorizationNearestPivotExpirySeconds($related);
            }
        };

        $expired           = new class extends Model {};
        $pivot             = new \stdClass;
        $pivot->expires_at = '1990-01-01 00:00:00';
        $expired->setRelation('pivot', $pivot);

        $noExpiry = new class extends Model {};
        $noPivot  = new \stdClass;
        $noExpiry->setRelation('pivot', $noPivot);

        self::assertNull($probe->nearest([$expired, $noExpiry]));
    }

    /**
     * `authorizationMinNullable` returns the smaller value, treats null as "no
     * bound". Pins the min-branch against arithmetic mutants and
     * null-left/right swap mutants.
     *
     * @return void
     */
    public function testMinNullableRespectsNullAsUnbounded(): void
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @param  ?int  $l
             * @param  ?int  $r
             * @return int|null
             */
            public function min(?int $l, ?int $r): ?int
            {
                return self::authorizationMinNullable($l, $r);
            }
        };

        self::assertSame(1, $probe->min(1, 2));
        self::assertSame(1, $probe->min(2, 1));
        self::assertSame(3, $probe->min(null, 3));
        self::assertSame(3, $probe->min(3, null));
        self::assertNull($probe->min(null, null));

        // Equal values — left == right, result equals both.
        self::assertSame(5, $probe->min(5, 5));
    }

    /**
     * `authorizationCoerceExpiresAt` returns a Carbon for strings and DateTime
     * values, null for everything else. Pins the string-not-empty and DateTime
     * instanceof branches.
     *
     * @return void
     */
    public function testCoerceExpiresAtCoerciveBranches(): void
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @param  mixed  $raw
             * @return mixed
             */
            public function coerce(mixed $raw): mixed
            {
                return self::authorizationCoerceExpiresAt($raw);
            }
        };

        $timestamp = $probe->coerce('2026-06-01 12:00:00');
        self::assertInstanceOf(Carbon::class, $timestamp);
        self::assertSame('2026-06-01 12:00:00', $timestamp->toDateTimeString());

        $source    = new \DateTimeImmutable('2025-01-01 00:00:00');
        $timestamp = $probe->coerce($source);
        self::assertInstanceOf(Carbon::class, $timestamp);
        self::assertSame('2025-01-01 00:00:00', $timestamp->toDateTimeString());

        self::assertNull($probe->coerce(null));
        self::assertNull($probe->coerce(''));
        self::assertNull($probe->coerce(0));
        self::assertNull($probe->coerce(42));
        self::assertNull($probe->coerce(new \stdClass));
    }

    /**
     * `authorizationSecondsUntilPivotExpiry` subtracts `nowTimestamp` from the
     * pivot expiry and returns null when the result is zero or negative. Pins
     * the `> 0` branch against `>= 0` mutants.
     *
     * @return void
     */
    public function testSecondsUntilPivotExpiryDropsZeroAndNegative(): void
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @param  \Illuminate\Database\Eloquent\Model  $model
             * @param  int  $now
             * @return int|null
             */
            public function seconds(Model $model, int $now): ?int
            {
                return self::authorizationSecondsUntilPivotExpiry($model, $now);
            }
        };

        $mk = static function (string $expiresAt): Model {
            $model             = new class extends Model {};
            $pivot             = new \stdClass;
            $pivot->expires_at = $expiresAt;
            $model->setRelation('pivot', $pivot);

            return $model;
        };

        $now = Carbon::parse('2026-01-01 00:00:00')->getTimestamp();

        // 30 seconds in the future.
        self::assertSame(30, $probe->seconds($mk('2026-01-01 00:00:30'), $now));
        // Exactly at `now` — returns null (seconds <= 0).
        self::assertNull($probe->seconds($mk('2026-01-01 00:00:00'), $now));
        // 5 seconds in the past.
        self::assertNull($probe->seconds($mk('2025-12-31 23:59:55'), $now));
    }

    /**
     * `areAuthorizationGrantExpiriesEqual` compares two DateTimes by UTC
     * timestamp and treats two nulls as equal. Pins every equality branch
     * against mutation.
     *
     * @return void
     */
    public function testGrantExpiriesEqualEveryBranch(): void
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @param  ?\DateTimeInterface  $l
             * @param  ?\DateTimeInterface  $r
             * @return bool
             */
            public function areEqual(?\DateTimeInterface $l, ?\DateTimeInterface $r): bool
            {
                return self::areAuthorizationGrantExpiriesEqual($l, $r);
            }
        };

        $a = new \DateTimeImmutable('2026-06-01 12:00:00', new \DateTimeZone('UTC'));
        $b = new \DateTimeImmutable('2026-06-01 12:00:00', new \DateTimeZone('UTC'));
        $c = new \DateTimeImmutable('2026-06-01 12:00:01', new \DateTimeZone('UTC'));

        self::assertTrue($probe->areEqual(null, null));
        self::assertFalse($probe->areEqual($a, null));
        self::assertFalse($probe->areEqual(null, $a));
        self::assertTrue($probe->areEqual($a, $b));
        self::assertFalse($probe->areEqual($a, $c));
    }

    /**
     * `ResolutionCache::resolveTtl` returns `[true, 0]` for a
     * forever-configured cache with no `$maxTtl`, `[false, ttl]` when just the
     * config applies, and `[false, min - 1]` when `$maxTtl` bounds the window.
     * Pins the subtraction-of-1, min comparison, and forever short-circuit.
     *
     * @return void
     */
    public function testResolveTtlMatrix(): void
    {
        $invoke = static function (int $configuredTtl, ?int $maxTtl): array {
            $cache = new ResolutionCache(store: null, ttl: $configuredTtl);

            $ref = new \ReflectionMethod($cache, 'resolveTtl');

            /** @var array{0: bool, 1: int} */
            return $ref->invoke($cache, $maxTtl);
        };

        // Default constructor ttl is 0 (forever). `new ResolutionCache()`
        // without explicit ttl resolves to the forever branch. Pins the default
        // parameter value against IncrementInteger mutation.
        $defaultCache = new ResolutionCache(store: null);
        $defaultRef   = new \ReflectionMethod($defaultCache, 'resolveTtl');
        self::assertSame([true, 0], $defaultRef->invoke($defaultCache, null));

        // Forever (ttl=0) + no maxTtl: forever short-circuit.
        self::assertSame([true, 0], $invoke(0, null));

        // Positive ttl + no maxTtl: use ttl verbatim.
        self::assertSame([false, 3600], $invoke(3600, null));

        // Forever (ttl=0) + maxTtl: bound by maxTtl - 1.
        self::assertSame([false, 59], $invoke(0, 60));

        // Positive ttl, maxTtl smaller: maxTtl wins, minus 1.
        self::assertSame([false, 29], $invoke(600, 30));

        // Positive ttl, maxTtl larger: ttl wins, minus 1.
        self::assertSame([false, 599], $invoke(600, 3600));

        // Equal ttl and maxTtl: either wins, minus 1.
        self::assertSame([false, 99], $invoke(100, 100));

        // maxTtl <= 0 ends up negative/zero — caller skips the put.
        self::assertSame([false, -1], $invoke(0, 0));
    }

    /**
     * `ResolutionCache::supportsTags` reports the tag capability of the
     * configured store and memoises the probe. Pins the memo short-circuit so
     * `PropertyAssign` / `Coalesce` mutations break.
     *
     * @return void
     */
    public function testSupportsTagsReflectsConfiguredStore(): void
    {
        $cache = new ResolutionCache(store: null);
        self::assertFalse($cache->supportsTags());

        $cache = new ResolutionCache(store: Cache::store('array'));
        self::assertTrue($cache->supportsTags());
        // Second call exercises the memoised branch.
        self::assertTrue($cache->supportsTags());
    }

    /**
     * `forgetRoleTags()` on a taggable store emits a tag-flush call exactly
     * once per role with a non-empty key. Pins both the empty-key skip and the
     * tag-flush side effect.
     *
     * @return void
     */
    public function testForgetRoleTagsFlushesTaggedStoreForNonEmptyKey(): void
    {
        $cache     = new ResolutionCache(store: Cache::store('array'), prefix: 'authorization-test');
        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'r1', 'guard_name' => 'web']);

        // Prime the cache so the tag namespace has something to flush.
        $cache->rememberPermissions(
            $principal,
            static fn (): array => ['x:do'],
            new ResolutionCacheContext(maxTtl: null, roleIds: [(string) $role->getKey()]), // @phpstan-ignore cast.string
        );

        // Flush the role's tag — subsequent read on fresh cache misses.
        $cache->forgetRoleTags($role);

        $fresh     = new ResolutionCache(store: Cache::store('array'), prefix: 'authorization-test');
        $calls     = 0;
        $collected = $fresh->rememberPermissions(
            $principal,
            static function () use (&$calls): array {
                $calls++;

                return ['y:do'];
            },
            new ResolutionCacheContext(maxTtl: null, roleIds: [(string) $role->getKey()]), // @phpstan-ignore cast.string
        );

        self::assertSame(['y:do'], $collected);
        self::assertSame(1, $calls, 'Resolver should run because tagged-flush invalidated the entry.');
    }

    /**
     * `assignRole()` fires `IdentityRoleAssigned` exactly once for a first-time
     * grant and does not re-fire if the expiry is unchanged — pins the
     * expiry-equality branch.
     *
     * @return void
     */
    public function testAssignRoleIsIdempotentWhenExpiryUnchanged(): void
    {
        Event::fake(
            [RoleExpiryChanged::class],
        );

        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'idem', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Anchor Carbon so the computed expiry is deterministic and identical
        // across both calls — avoids wall-clock drift.
        Carbon::setTestNow('2026-01-01 00:00:00');

        try {
            $expires = Carbon::now()->addHour()->toDateTimeImmutable();
            $user->assignRole($role, $expires);
            $user->assignRole($role, $expires);
        } finally {
            Carbon::setTestNow();
        }

        Event::assertNotDispatched(
            RoleExpiryChanged::class,
        );
    }

    /**
     * `assignRole()` with a different expiry fires `IdentityRoleExpiryChanged`
     * — pins the `!grantExpiriesEqual` branch against LogicalAnd/Negation
     * mutations.
     *
     * @return void
     */
    public function testAssignRoleFiresExpiryChangedWhenWindowMoves(): void
    {
        Event::fake(
            [RoleExpiryChanged::class],
        );

        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'moving', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Anchor Carbon so the two expiries are computed against a fixed
        // instant — keeps the +1h vs +2h delta deterministic.
        Carbon::setTestNow('2026-01-01 00:00:00');

        try {
            $user->assignRole($role, Carbon::now()->addHour()->toDateTimeImmutable());
            $user->assignRole($role, Carbon::now()->addHours(2)->toDateTimeImmutable());
        } finally {
            Carbon::setTestNow();
        }

        Event::assertDispatchedTimes(
            RoleExpiryChanged::class,
            1,
        );
    }

    /**
     * `givePermission()` with a different expiry fires
     * `IdentityPermissionExpiryChanged`.
     *
     * @return void
     */
    public function testGivePermissionFiresExpiryChangedWhenWindowMoves(): void
    {
        Event::fake(
            [PermissionExpiryChanged::class],
        );

        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'p:m', 'guard_name' => 'web']);
        $user       = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Anchor Carbon so the two expiries are computed against a fixed
        // instant — keeps the +1h vs +2h delta deterministic.
        Carbon::setTestNow('2026-01-01 00:00:00');

        try {
            $user->givePermission($permission, Carbon::now()->addHour()->toDateTimeImmutable());
            $user->givePermission($permission, Carbon::now()->addHours(2)->toDateTimeImmutable());
        } finally {
            Carbon::setTestNow();
        }

        Event::assertDispatchedTimes(
            PermissionExpiryChanged::class,
            1,
        );
    }

    /**
     * `authorizationResolveGrantPivotColumns` reads the per-pivot column map
     * from `authorization.pivots.<pivot>.<column>`. A custom override at each
     * config path is applied — pins every concat operand in the prefix assembly
     * (line 224) and each `$prefix . 'column'` call.
     *
     * @return void
     */
    public function testAuthorizationResolveGrantPivotColumnsHonoursPerPivotOverrides(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(Repository::class); // @phpstan-ignore method.nonObject

        $config->set('authorization.pivots.authorizable_roles.authorizable_type_column', 'custom_type');
        $config->set('authorization.pivots.authorizable_roles.authorizable_id_column', 'custom_id');
        $config->set('authorization.pivots.authorizable_roles.role_column', 'custom_role_fk');
        $config->set('authorization.pivots.authorizable_roles.expires_at_column', 'custom_expires_at');

        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @return array<string, mixed>
             */
            public function columns(): array
            {
                return self::authorizationResolveGrantPivotColumns('authorizable_roles', 'role_column', 'role_id');
            }
        };

        $columns = $probe->columns();

        self::assertSame('custom_type', $columns['authorizable_type']);
        self::assertSame('custom_id', $columns['authorizable_id']);
        self::assertSame('custom_role_fk', $columns['target']);
        self::assertSame('custom_expires_at', $columns['expires_at']);
    }

    /**
     * Without an override, `authorizationResolveGrantPivotColumns` returns the
     * package defaults for each column. Pins the default values passed as
     * second argument to each `config()` call.
     *
     * @return void
     */
    public function testAuthorizationResolveGrantPivotColumnsDefaultsToPackageColumns(): void
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @param  string  $pivot
             * @param  string  $targetKey
             * @param  string  $defaultTarget
             * @return array<string, mixed>
             */
            public function columns(string $pivot, string $targetKey, string $defaultTarget): array
            {
                return self::authorizationResolveGrantPivotColumns($pivot, $targetKey, $defaultTarget);
            }
        };

        $columns = $probe->columns('some_new_pivot', 'custom_key', 'custom_default');

        self::assertSame('authorizable_type', $columns['authorizable_type']);
        self::assertSame('authorizable_id', $columns['authorizable_id']);
        self::assertSame('custom_default', $columns['target']);
        self::assertSame('expires_at', $columns['expires_at']);
    }

    /**
     * The cache key is built as `<prefix>:<kind>:<morph>:<id>` — targeted
     * assertions pin the exact shape so concat-removal and concat-reorder
     * mutations around `keyFor()` break.
     *
     * @return void
     */
    public function testCacheKeyShapeIsPrefixKindMorphId(): void
    {
        $driver = new NonTaggableCacheStore;
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'km-test');

        // A principal exposing getMorphClass + getKey should key as
        // `<prefix>:<kind>:<morph>:<id>`.
        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'widget';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return 'abc';
            }
        };

        $cache->rememberPermissions($principal, static fn (): array => ['x:do']);
        self::assertArrayHasKey('km-test:permissions:widget:abc', $driver->storage);

        $cache->rememberRoles($principal, static fn (): array => ['r']);
        self::assertArrayHasKey('km-test:roles:widget:abc', $driver->storage);

        $cache->rememberPolicies($principal, static fn (): array => []);
        self::assertArrayHasKey('km-test:policies:widget:abc', $driver->storage);
    }

    /**
     * When a principal lacks `getMorphClass`, the key falls back to
     * `<FQCN>:<id>` — pins the type coalesce against Coalesce mutants.
     *
     * @return void
     */
    public function testCacheKeyShapeFallsBackToClassNameWhenMorphMissing(): void
    {
        $driver = new NonTaggableCacheStore;
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'km');

        $principal = new class {
            /**
             * @return string
             */
            public function getKey(): string
            {
                return '77';
            }
        };

        $cache->rememberPermissions($principal, static fn (): array => []);

        $class = $principal::class;
        self::assertArrayHasKey("km:permissions:{$class}:77", $driver->storage);
    }

    /**
     * `Statement::fromArray` distinguishes between missing and wrong-type
     * effect values — pins the `!isset($x) || !is_string` branch against `&&`
     * mutants.
     *
     * @return void
     */
    public function testStatementResolveEffectRejectsMissingAndNonString(): void
    {
        // Missing.
        $this->expectExceptionObjectShape(
            static fn () => Statement::fromArray([
                'actions' => ['x'],
            ]),
            \InvalidArgumentException::class,
            'Policy statement requires a string effect.',
        );

        // Present but non-string.
        $this->expectExceptionObjectShape(
            static fn () => Statement::fromArray([
                'effect'  => 42,
                'actions' => ['x'],
            ]),
            \InvalidArgumentException::class,
            'Policy statement requires a string effect.',
        );
    }

    /**
     * `Statement::fromArray` rejects missing, non-array, and empty actions —
     * pins each of the three `||` sub-expressions.
     *
     * @return void
     */
    public function testStatementResolveActionsRejectsAllThreeBranches(): void
    {
        // Missing.
        $this->expectExceptionObjectShape(
            static fn () => Statement::fromArray([
                'effect' => 'allow',
            ]),
            \InvalidArgumentException::class,
            'Policy statement requires at least one action.',
        );

        // Not array.
        $this->expectExceptionObjectShape(
            static fn () => Statement::fromArray([
                'effect'  => 'allow',
                'actions' => 'x',
            ]),
            \InvalidArgumentException::class,
            'Policy statement requires at least one action.',
        );

        // Empty array.
        $this->expectExceptionObjectShape(
            static fn () => Statement::fromArray([
                'effect'  => 'allow',
                'actions' => [],
            ]),
            \InvalidArgumentException::class,
            'Policy statement requires at least one action.',
        );
    }

    /**
     * An invalid effect string yields the correctly quoted message. Pins the
     * trailing `:'{$data['effect']}'` concat.
     *
     * @return void
     */
    public function testStatementUnknownEffectQuotesOffendingValue(): void
    {
        try {
            Statement::fromArray([
                'effect'  => 'maybe',
                'actions' => ['x'],
            ]);
            self::fail('Expected InvalidArgumentException.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Invalid policy effect: \'maybe\'', $exception->getMessage());
        }
    }

    /**
     * Default `resources` value is `['*']`. Pins the `public array $resources =
     * ['*'];` default against ArrayItemRemoval.
     *
     * @return void
     */
    public function testStatementDefaultResourcesWildcard(): void
    {
        $statement = Statement::fromArray([
            'effect'  => 'allow',
            'actions' => ['x'],
        ]);

        self::assertSame(['*'], $statement->resources);
    }

    /**
     * `matchesNumericComparison` returns false for non-numeric actual / operand
     * inputs, and performs strict comparison for numeric values.
     *
     * @return void
     */
    public function testCompareNumericAcrossOperatorMatrix(): void
    {
        self::assertFalse(ConditionEvaluator::matchesNumericComparison('abc', 5, '>'));
        self::assertFalse(ConditionEvaluator::matchesNumericComparison(5, 'abc', '>'));

        self::assertTrue(ConditionEvaluator::matchesNumericComparison(10, 5, '>'));
        self::assertFalse(ConditionEvaluator::matchesNumericComparison(5, 5, '>'));
        self::assertTrue(ConditionEvaluator::matchesNumericComparison(5, 5, '>='));
        self::assertTrue(ConditionEvaluator::matchesNumericComparison(5, 10, '<'));
        self::assertTrue(ConditionEvaluator::matchesNumericComparison(5, 5, '<='));
        self::assertFalse(ConditionEvaluator::matchesNumericComparison(5, 5, 'unknown'));
    }

    /**
     * `matchesBool` coerces both sides before equality — pins the symmetric
     * coercion against mutants that skip one side.
     *
     * @return void
     */
    public function testMatchesBoolCoercesBothSidesSymmetrically(): void
    {
        $cls = ConditionEvaluator::class;

        self::assertTrue($cls::matchesBool(true, 'true'));
        self::assertTrue($cls::matchesBool('1', 1));
        self::assertTrue($cls::matchesBool(false, 'no'));
        self::assertTrue($cls::matchesBool('anything-else', 0));
        self::assertFalse($cls::matchesBool(true, false));
        self::assertFalse($cls::matchesBool(false, true));
    }

    /**
     * `matchesCidr` handles exact-match, /0 mask, /32 mask, and bad-input
     * cases. Pins the `0 ? 0 : (-1 << (32 - $bits))` ternary.
     *
     * @return void
     */
    public function testMatchesCidrMatrix(): void
    {
        $cls = ConditionEvaluator::class;

        // Exact match with no slash.
        self::assertTrue($cls::matchesCidr('10.0.0.1', '10.0.0.1'));
        self::assertFalse($cls::matchesCidr('10.0.0.1', '10.0.0.2'));

        // /0 matches everything.
        self::assertTrue($cls::matchesCidr('8.8.8.8', '0.0.0.0/0'));
        self::assertTrue($cls::matchesCidr('255.255.255.255', '0.0.0.0/0'));

        // /32 matches only exact.
        self::assertTrue($cls::matchesCidr('1.2.3.4', '1.2.3.4/32'));
        self::assertFalse($cls::matchesCidr('1.2.3.5', '1.2.3.4/32'));

        // Bad IP.
        self::assertFalse($cls::matchesCidr('not-an-ip', '10.0.0.0/8'));

        // Bad bits.
        self::assertFalse($cls::matchesCidr('10.0.0.1', '10.0.0.0/abc'));

        // Bits too big.
        self::assertFalse($cls::matchesCidr('10.0.0.1', '10.0.0.0/64'));
    }

    /**
     * `matchesTimeComparison` uses the `<` / `>` comparator; anything else
     * returns false. Pins the default-arm `false` against FalseValue /
     * MatchArmRemoval mutants.
     *
     * @return void
     */
    public function testCompareTimesDefaultArmReturnsFalse(): void
    {
        $cls = ConditionEvaluator::class;

        self::assertTrue($cls::matchesTimeComparison('2026-01-01', '2026-06-01', '<'));
        self::assertTrue($cls::matchesTimeComparison('2026-06-01', '2026-01-01', '>'));
        self::assertFalse($cls::matchesTimeComparison('2026-01-01', '2026-06-01', '>'));
        self::assertFalse($cls::matchesTimeComparison('2026-06-01', '2026-01-01', '<'));

        // Default arm.
        self::assertFalse($cls::matchesTimeComparison('2026-01-01', '2026-06-01', '=='));
        self::assertFalse($cls::matchesTimeComparison('2026-01-01', '2026-06-01', 'unknown'));

        // Null timestamps fail closed.
        self::assertFalse($cls::matchesTimeComparison('not-a-time', '2026-06-01', '<'));
        self::assertFalse($cls::matchesTimeComparison('2026-01-01', 'not-a-time', '<'));
    }

    /**
     * `matchesBetween` requires both bounds; returns false on missing operand
     * keys, malformed operand, or out-of-range values. Pins the `>=` and `<=`
     * inclusive bounds.
     *
     * @return void
     */
    public function testMatchesBetweenRequiresBothBoundsAndInclusive(): void
    {
        $cls = ConditionEvaluator::class;

        self::assertTrue($cls::matchesBetween('2026-06-15', ['2026-06-01', '2026-06-30']));

        // Inclusive lower bound.
        self::assertTrue($cls::matchesBetween('2026-06-01', ['2026-06-01', '2026-06-30']));
        // Inclusive upper bound.
        self::assertTrue($cls::matchesBetween('2026-06-30', ['2026-06-01', '2026-06-30']));

        // Just outside.
        self::assertFalse($cls::matchesBetween('2026-05-31', ['2026-06-01', '2026-06-30']));
        self::assertFalse($cls::matchesBetween('2026-07-01', ['2026-06-01', '2026-06-30']));

        // Missing operand keys.
        self::assertFalse($cls::matchesBetween('2026-06-15', ['2026-06-01']));
        self::assertFalse($cls::matchesBetween('2026-06-15', 'not-array'));

        // Unparseable operand.
        self::assertFalse($cls::matchesBetween('2026-06-15', ['bad', '2026-06-30']));
        self::assertFalse($cls::matchesBetween('not-a-time', ['2026-06-01', '2026-06-30']));
    }

    /**
     * `authorize()` populates the `LastDecisionStore` on both the success and
     * deny paths — pins the MethodCallRemoval mutant on
     * `$this->lastDecisionStore->put($collected)` inside the `authorize` branch
     * (not evaluate).
     *
     * @return void
     */
    public function testAuthorizeWritesLastDecisionOnBothOutcomes(): void
    {
        $this->app->make(LastDecisionStore::class)->forget(); // @phpstan-ignore method.nonObject

        // Deny path — authorize() throws, lastDecision captures the result.
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'la', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        try {
            Authorization::for($user)->authorize('forbidden:action');
            self::fail('Expected AuthorizationException.');
        } catch (AuthorizationException) {
            $last = Authorization::lastDecision();
            self::assertNotNull($last);
            self::assertFalse($last->allowed);
        }

        // Allow path — authorize() returns, lastDecision captures allow.
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'allow:me', 'guard_name' => 'web']);
        $role->givePermission($permission);
        $user->assignRole($role);

        Authorization::for($user->fresh())->authorize('allow:me');

        $last = Authorization::lastDecision();
        self::assertNotNull($last);
        self::assertTrue($last->allowed);
    }

    /**
     * `withPolicies()` returns a cloned manager — pins the CloneRemoval mutant
     * on `$scoped = clone $this;`. The two managers must be distinct instances.
     *
     * @return void
     */
    public function testWithPoliciesReturnsDistinctClone(): void
    {
        $manager = Authorization::getFacadeRoot();
        self::assertInstanceOf(AuthorizationManager::class, $manager);

        $policy = new Policy(
            name: 'clone-probe',
            statements: [
                new Statement(
                    effect: PolicyEffect::ALLOW,
                    actions: ['probe:clone'],
                ),
            ],
        );

        $scoped = $manager->withPolicies([$policy]);

        // Clones are distinct objects — pins CloneRemoval.
        self::assertNotSame($manager, $scoped);

        // The scoped clone evaluates through the supplied policies and yields
        // allow; the base does not.
        $scopedPrincipal = StubIdentity::create(['id' => (string) Str::uuid()]);
        self::assertTrue($scoped->for($scopedPrincipal)->can('probe:clone'));
        self::assertFalse($manager->for($scopedPrincipal)->can('probe:clone'));
    }

    /**
     * `attachPolicy()` with a different expiry fires
     * `IdentityPolicyExpiryChanged`.
     *
     * @return void
     */
    public function testAttachPolicyFiresExpiryChangedWhenWindowMoves(): void
    {
        Event::fake(
            [PolicyExpiryChanged::class],
        );

        $policy = \SineMacula\Laravel\Authorization\Models\Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'policy-m',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Anchor Carbon so the two expiries are computed against a fixed
        // instant — keeps the +1h vs +2h delta deterministic.
        Carbon::setTestNow('2026-01-01 00:00:00');

        try {
            $user->attachPolicy($policy, Carbon::now()->addHour()->toDateTimeImmutable());
            $user->attachPolicy($policy, Carbon::now()->addHours(2)->toDateTimeImmutable());
        } finally {
            Carbon::setTestNow();
        }

        Event::assertDispatchedTimes(
            PolicyExpiryChanged::class,
            1,
        );
    }

    /**
     * Run a callable and assert it throws the expected exception class with the
     * expected message. Shared helper for the `resolveEffect` /
     * `resolveActions` branches.
     *
     * @param  callable(): mixed  $callable
     * @param  class-string<\Throwable>  $class
     * @param  string  $message
     * @return void
     */
    private function expectExceptionObjectShape(callable $callable, string $class, string $message): void
    {
        try {
            $callable();
            self::fail("Expected exception {$class}.");
        } catch (\Throwable $exception) {
            self::assertInstanceOf($class, $exception);
            self::assertStringContainsString($message, $exception->getMessage());
        }
    }

    /**
     * Build a throwaway Eloquent model whose `getKey()` returns the supplied
     * value — fixture helper for the collect-ids test matrix (integer / string
     * / duplicate / empty / non-scalar).
     *
     * @param  mixed  $key
     * @return \Illuminate\Database\Eloquent\Model
     */
    private function makeModelWithKey(mixed $key): Model
    {
        $model = new class extends Model {
            /** @var mixed */
            public mixed $fixedKey = null;

            /**
             * @return mixed
             */
            #[\Override]
            public function getKey(): mixed
            {
                return $this->fixedKey;
            }
        };

        $model->fixedKey = $key;

        return $model;
    }
}
