<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasPolicies;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use SineMacula\Laravel\Authorization\Traits\ResolvesPivotExpiry;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Mutation-killer feature tests targeting the `ResolvesPivotExpiry`
 * helper, the `ResolutionCache` TTL / key routing, and the
 * authorizable-identity trait branches whose semantic mutants
 * escaped the initial mutation sweep.
 *
 * These tests assert exact values (counts, keys, time bounds) so
 * subtle mutations — `<` vs `<=`, `||` vs `&&`, off-by-one on
 * integer literals, cast removal — surface as failures rather
 * than silently passing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversTrait(HasPolicies::class)]
#[CoversTrait(ResolvesPivotExpiry::class)]
#[CoversClass(ResolutionCache::class)]
final class MutationKillersTest extends TestCase
{
    /**
     * `authorizationCollectModelIds` stringifies integer keys, drops
     * empty strings, and dedupes. The assertions pin all three
     * behaviours so a logical / cast / unique mutant breaks.
     *
     * @return void
     */
    public function testCollectModelIdsStringifiesAndDedupesAndDropsEmpty(): void
    {
        $probe = new class {
            use ResolvesPivotExpiry;

            /** @param  iterable<int, Model>  $models */
            public function collect(iterable $models): array
            {
                return self::authorizationCollectModelIds($models);
            }
        };

        $integerKeyed = new class extends Model {
            public function getKey(): mixed
            {
                return 42;
            }
        };

        $stringKeyed = new class extends Model {
            public function getKey(): mixed
            {
                return 'alpha';
            }
        };

        $stringKeyedDupe = new class extends Model {
            public function getKey(): mixed
            {
                return 'alpha';
            }
        };

        $emptyString = new class extends Model {
            public function getKey(): mixed
            {
                return '';
            }
        };

        $objectKey = new class extends Model {
            public function getKey(): mixed
            {
                return new \stdClass;
            }
        };

        $result = $probe->collect([$integerKeyed, $stringKeyed, $stringKeyedDupe, $emptyString, $objectKey]);

        // Integer 42 must be cast to string '42'; empties dropped;
        // duplicates squashed; non-string/non-int keys skipped.
        self::assertSame(['42', 'alpha'], $result);
    }

    /**
     * `authorizationCollectModelIds` returns an empty array when
     * every model is malformed — pins the foreach iteration against
     * Foreach_ / break mutants.
     *
     * @return void
     */
    public function testCollectModelIdsReturnsEmptyForAllMalformedModels(): void
    {
        $probe = new class {
            use ResolvesPivotExpiry;

            /** @param  iterable<int, Model>  $models */
            public function collect(iterable $models): array
            {
                return self::authorizationCollectModelIds($models);
            }
        };

        $empty = new class extends Model {
            public function getKey(): mixed
            {
                return '';
            }
        };

        $obj = new class extends Model {
            public function getKey(): mixed
            {
                return new \stdClass;
            }
        };

        self::assertSame([], $probe->collect([$empty, $obj, $empty]));
    }

    /**
     * `authorizationNearestPivotExpirySeconds` returns the smallest
     * positive seconds-until-expiry across pivot rows. Pins the
     * strict less-than comparison against `<=` mutants.
     *
     * @return void
     */
    public function testNearestPivotExpirySelectsStrictlySmallerSeconds(): void
    {
        $probe = new class {
            use ResolvesPivotExpiry;

            /** @param  iterable<int, Model>  $related */
            public function nearest(iterable $related): ?int
            {
                return self::authorizationNearestPivotExpirySeconds($related);
            }
        };

        $now = \Illuminate\Support\Carbon::now();

        $mk = static function (int $seconds) use ($now): Model {
            $model                   = new class extends Model {};
            $pivot                   = new \stdClass;
            $pivot->expires_at       = (clone $now)->addSeconds($seconds)->toDateTimeString();
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
     * `authorizationNearestPivotExpirySeconds` returns null when no
     * pivot row carries a live expiry — pins the null-return
     * against ReturnRemoval / null-default mutants.
     *
     * @return void
     */
    public function testNearestPivotExpiryReturnsNullWhenNoLiveExpiries(): void
    {
        $probe = new class {
            use ResolvesPivotExpiry;

            /** @param  iterable<int, Model>  $related */
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
     * `authorizationMinNullable` returns the smaller value, treats
     * null as "no bound". Pins the min-branch against arithmetic
     * mutants and null-left/right swap mutants.
     *
     * @return void
     */
    public function testMinNullableRespectsNullAsUnbounded(): void
    {
        $probe = new class {
            use ResolvesPivotExpiry;

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
     * `authorizationCoerceExpiresAt` returns a Carbon for strings
     * and DateTime values, null for everything else. Pins the
     * string-not-empty and DateTime instanceof branches.
     *
     * @return void
     */
    public function testCoerceExpiresAtCoerciveBranches(): void
    {
        $probe = new class {
            use ResolvesPivotExpiry;

            public function coerce(mixed $raw): mixed
            {
                return self::authorizationCoerceExpiresAt($raw);
            }
        };

        $ts = $probe->coerce('2026-06-01 12:00:00');
        self::assertInstanceOf(\Illuminate\Support\Carbon::class, $ts);
        self::assertSame('2026-06-01 12:00:00', $ts->toDateTimeString());

        $dt = new \DateTimeImmutable('2025-01-01 00:00:00');
        $ts = $probe->coerce($dt);
        self::assertInstanceOf(\Illuminate\Support\Carbon::class, $ts);
        self::assertSame('2025-01-01 00:00:00', $ts->toDateTimeString());

        self::assertNull($probe->coerce(null));
        self::assertNull($probe->coerce(''));
        self::assertNull($probe->coerce(0));
        self::assertNull($probe->coerce(42));
        self::assertNull($probe->coerce(new \stdClass));
    }

    /**
     * `authorizationSecondsUntilPivotExpiry` subtracts `nowTimestamp`
     * from the pivot expiry and returns null when the result is zero
     * or negative. Pins the `> 0` branch against `>= 0` mutants.
     *
     * @return void
     */
    public function testSecondsUntilPivotExpiryDropsZeroAndNegative(): void
    {
        $probe = new class {
            use ResolvesPivotExpiry;

            public function seconds(Model $model, int $now): ?int
            {
                return self::authorizationSecondsUntilPivotExpiry($model, $now);
            }
        };

        $mk = static function (string $expiresAt): Model {
            $model                   = new class extends Model {};
            $pivot                   = new \stdClass;
            $pivot->expires_at       = $expiresAt;
            $model->setRelation('pivot', $pivot);

            return $model;
        };

        $now = \Illuminate\Support\Carbon::parse('2026-01-01 00:00:00')->getTimestamp();

        // 30 seconds in the future.
        self::assertSame(30, $probe->seconds($mk('2026-01-01 00:00:30'), $now));
        // Exactly at `now` — returns null (seconds <= 0).
        self::assertNull($probe->seconds($mk('2026-01-01 00:00:00'), $now));
        // 5 seconds in the past.
        self::assertNull($probe->seconds($mk('2025-12-31 23:59:55'), $now));
    }

    /**
     * `authorizationGrantExpiriesEqual` compares two DateTimes by
     * UTC timestamp and treats two nulls as equal. Pins every
     * equality branch against mutation.
     *
     * @return void
     */
    public function testGrantExpiriesEqualEveryBranch(): void
    {
        $probe = new class {
            use ResolvesPivotExpiry;

            public function equal(?\DateTimeInterface $l, ?\DateTimeInterface $r): bool
            {
                return self::authorizationGrantExpiriesEqual($l, $r);
            }
        };

        $a = new \DateTimeImmutable('2026-06-01 12:00:00', new \DateTimeZone('UTC'));
        $b = new \DateTimeImmutable('2026-06-01 12:00:00', new \DateTimeZone('UTC'));
        $c = new \DateTimeImmutable('2026-06-01 12:00:01', new \DateTimeZone('UTC'));

        self::assertTrue($probe->equal(null, null));
        self::assertFalse($probe->equal($a, null));
        self::assertFalse($probe->equal(null, $a));
        self::assertTrue($probe->equal($a, $b));
        self::assertFalse($probe->equal($a, $c));
    }

    /**
     * `ResolutionCache::resolveTtl` returns `[true, 0]` for a
     * forever-configured cache with no `$maxTtl`, `[false, ttl]`
     * when just the config applies, and `[false, min - 1]` when
     * `$maxTtl` bounds the window. Pins the subtraction-of-1,
     * min comparison, and forever short-circuit.
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
     * `ResolutionCache::supportsTags` reports the tag capability of
     * the configured store and memoises the probe. Pins the memo
     * short-circuit so `PropertyAssign` / `Coalesce` mutations break.
     *
     * @return void
     */
    public function testSupportsTagsReflectsConfiguredStore(): void
    {
        $cache = new ResolutionCache(store: null);
        self::assertFalse($cache->supportsTags());

        $cache = new ResolutionCache(store: \Illuminate\Support\Facades\Cache::store('array'));
        self::assertTrue($cache->supportsTags());
        // Second call exercises the memoised branch.
        self::assertTrue($cache->supportsTags());
    }

    /**
     * `forgetRoleTags()` on a taggable store emits a tag-flush
     * call exactly once per role with a non-empty key. Pins both
     * the empty-key skip and the tag-flush side effect.
     *
     * @return void
     */
    public function testForgetRoleTagsFlushesTaggedStoreForNonEmptyKey(): void
    {
        $cache     = new ResolutionCache(store: \Illuminate\Support\Facades\Cache::store('array'), prefix: 'authorization-test');
        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'r1', 'guard_name' => 'web']);

        // Prime the cache so the tag namespace has something to flush.
        $cache->rememberPermissions(
            $principal,
            static fn (): array => ['x:do'],
            new ResolutionCacheContext(maxTtl: null, roleIds: [(string) $role->getKey()]),
        );

        // Flush the role's tag — subsequent read on fresh cache misses.
        $cache->forgetRoleTags($role);

        $fresh  = new ResolutionCache(store: \Illuminate\Support\Facades\Cache::store('array'), prefix: 'authorization-test');
        $calls  = 0;
        $result = $fresh->rememberPermissions(
            $principal,
            static function () use (&$calls): array {
                $calls++;

                return ['y:do'];
            },
            new ResolutionCacheContext(maxTtl: null, roleIds: [(string) $role->getKey()]),
        );

        self::assertSame(['y:do'], $result);
        self::assertSame(1, $calls, 'Resolver should run because tagged-flush invalidated the entry.');
    }

    /**
     * `assignRole()` fires `IdentityRoleAssigned` exactly once for
     * a first-time grant and does not re-fire if the expiry is
     * unchanged — pins the expiry-equality branch.
     *
     * @return void
     */
    public function testAssignRoleIsIdempotentWhenExpiryUnchanged(): void
    {
        \Illuminate\Support\Facades\Event::fake(
            [\SineMacula\Laravel\Authorization\Events\IdentityRoleExpiryChanged::class],
        );

        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'idem', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $expires = new \DateTimeImmutable('+1 hour');
        $user->assignRole($role, $expires);
        $user->assignRole($role, $expires);

        \Illuminate\Support\Facades\Event::assertNotDispatched(
            \SineMacula\Laravel\Authorization\Events\IdentityRoleExpiryChanged::class,
        );
    }

    /**
     * `assignRole()` with a different expiry fires
     * `IdentityRoleExpiryChanged` — pins the `!grantExpiriesEqual`
     * branch against LogicalAnd/Negation mutations.
     *
     * @return void
     */
    public function testAssignRoleFiresExpiryChangedWhenWindowMoves(): void
    {
        \Illuminate\Support\Facades\Event::fake(
            [\SineMacula\Laravel\Authorization\Events\IdentityRoleExpiryChanged::class],
        );

        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'moving', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->assignRole($role, new \DateTimeImmutable('+1 hour'));
        $user->assignRole($role, new \DateTimeImmutable('+2 hours'));

        \Illuminate\Support\Facades\Event::assertDispatchedTimes(
            \SineMacula\Laravel\Authorization\Events\IdentityRoleExpiryChanged::class,
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
        \Illuminate\Support\Facades\Event::fake(
            [\SineMacula\Laravel\Authorization\Events\IdentityPermissionExpiryChanged::class],
        );

        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'p:m', 'guard_name' => 'web']);
        $user       = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->givePermission($permission, new \DateTimeImmutable('+1 hour'));
        $user->givePermission($permission, new \DateTimeImmutable('+2 hours'));

        \Illuminate\Support\Facades\Event::assertDispatchedTimes(
            \SineMacula\Laravel\Authorization\Events\IdentityPermissionExpiryChanged::class,
            1,
        );
    }

    /**
     * The cache key is built as `<prefix>:<kind>:<morph>:<id>` —
     * targeted assertions pin the exact shape so concat-removal
     * and concat-reorder mutations around `keyFor()` break.
     *
     * @return void
     */
    public function testCacheKeyShapeIsPrefixKindMorphId(): void
    {
        $driver = new class implements \Illuminate\Contracts\Cache\Store {
            /** @var array<string, mixed> */
            public array $storage = [];

            public function get($key): mixed
            {
                return $this->storage[$key] ?? null;
            }

            public function many(array $keys): array
            {
                return [];
            }

            public function put($key, $value, $seconds): bool
            {
                $this->storage[$key] = $value;

                return true;
            }

            public function putMany(array $values, mixed $seconds): bool
            {
                return true;
            }

            public function increment($key, $value = 1): bool|int
            {
                return false;
            }

            public function decrement($key, $value = 1): bool|int
            {
                return false;
            }

            public function forever($key, $value): bool
            {
                $this->storage[$key] = $value;

                return true;
            }

            public function touch($key, $ttl): bool
            {
                return true;
            }

            public function forget($key): bool
            {
                unset($this->storage[$key]);

                return true;
            }

            public function flush(): bool
            {
                $this->storage = [];

                return true;
            }

            public function getPrefix(): string
            {
                return '';
            }
        };

        $store = new \Illuminate\Cache\Repository($driver);
        $cache = new ResolutionCache(store: $store, ttl: 0, prefix: 'km-test');

        // A principal exposing getMorphClass + getKey should key
        // as `<prefix>:<kind>:<morph>:<id>`.
        $principal = new class {
            public function getMorphClass(): string
            {
                return 'widget';
            }

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
     * When a principal lacks `getMorphClass`, the key falls back
     * to `<FQCN>:<id>` — pins the type coalesce against Coalesce
     * mutants.
     *
     * @return void
     */
    public function testCacheKeyShapeFallsBackToClassNameWhenMorphMissing(): void
    {
        $driver = new class implements \Illuminate\Contracts\Cache\Store {
            public array $storage = [];

            public function get($key): mixed
            {
                return $this->storage[$key] ?? null;
            }

            public function many(array $keys): array
            {
                return [];
            }

            public function put($key, $value, $seconds): bool
            {
                $this->storage[$key] = $value;

                return true;
            }

            public function putMany(array $values, mixed $seconds): bool
            {
                return true;
            }

            public function increment($key, $value = 1): bool|int
            {
                return false;
            }

            public function decrement($key, $value = 1): bool|int
            {
                return false;
            }

            public function forever($key, $value): bool
            {
                $this->storage[$key] = $value;

                return true;
            }

            public function touch($key, $ttl): bool
            {
                return true;
            }

            public function forget($key): bool
            {
                unset($this->storage[$key]);

                return true;
            }

            public function flush(): bool
            {
                $this->storage = [];

                return true;
            }

            public function getPrefix(): string
            {
                return '';
            }
        };

        $store = new \Illuminate\Cache\Repository($driver);
        $cache = new ResolutionCache(store: $store, ttl: 0, prefix: 'km');

        $principal = new class {
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
     * `Statement::fromArray` distinguishes between missing and
     * wrong-type effect values — pins the `!isset($x) || !is_string`
     * branch against `&&` mutants.
     *
     * @return void
     */
    public function testStatementResolveEffectRejectsMissingAndNonString(): void
    {
        // Missing.
        $this->expectExceptionObjectShape(
            static fn () => \SineMacula\Laravel\Authorization\Evaluation\Statement::fromArray([
                'actions' => ['x'],
            ]),
            \InvalidArgumentException::class,
            'Policy statement requires a string effect.',
        );

        // Present but non-string.
        $this->expectExceptionObjectShape(
            static fn () => \SineMacula\Laravel\Authorization\Evaluation\Statement::fromArray([
                'effect'  => 42,
                'actions' => ['x'],
            ]),
            \InvalidArgumentException::class,
            'Policy statement requires a string effect.',
        );
    }

    /**
     * `Statement::fromArray` rejects missing, non-array, and empty
     * actions — pins each of the three `||` sub-expressions.
     *
     * @return void
     */
    public function testStatementResolveActionsRejectsAllThreeBranches(): void
    {
        // Missing.
        $this->expectExceptionObjectShape(
            static fn () => \SineMacula\Laravel\Authorization\Evaluation\Statement::fromArray([
                'effect' => 'allow',
            ]),
            \InvalidArgumentException::class,
            'Policy statement requires at least one action.',
        );

        // Not array.
        $this->expectExceptionObjectShape(
            static fn () => \SineMacula\Laravel\Authorization\Evaluation\Statement::fromArray([
                'effect'  => 'allow',
                'actions' => 'x',
            ]),
            \InvalidArgumentException::class,
            'Policy statement requires at least one action.',
        );

        // Empty array.
        $this->expectExceptionObjectShape(
            static fn () => \SineMacula\Laravel\Authorization\Evaluation\Statement::fromArray([
                'effect'  => 'allow',
                'actions' => [],
            ]),
            \InvalidArgumentException::class,
            'Policy statement requires at least one action.',
        );
    }

    /**
     * An invalid effect string yields the correctly quoted
     * message. Pins the trailing `:'{$data['effect']}'` concat.
     *
     * @return void
     */
    public function testStatementUnknownEffectQuotesOffendingValue(): void
    {
        try {
            \SineMacula\Laravel\Authorization\Evaluation\Statement::fromArray([
                'effect'  => 'maybe',
                'actions' => ['x'],
            ]);
            self::fail('Expected InvalidArgumentException.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame("Invalid policy effect: 'maybe'", $exception->getMessage());
        }
    }

    /**
     * Default `resources` value is `['*']`. Pins the
     * `public array $resources = ['*'];` default against
     * ArrayItemRemoval.
     *
     * @return void
     */
    public function testStatementDefaultResourcesWildcard(): void
    {
        $statement = \SineMacula\Laravel\Authorization\Evaluation\Statement::fromArray([
            'effect'  => 'allow',
            'actions' => ['x'],
        ]);

        self::assertSame(['*'], $statement->resources);
    }

    /**
     * `compareNumeric` returns false for non-numeric actual /
     * operand inputs, and performs strict comparison for numeric.
     *
     * @return void
     */
    public function testCompareNumericAcrossOperatorMatrix(): void
    {
        self::assertFalse(\SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::compareNumeric('abc', 5, '>'));
        self::assertFalse(\SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::compareNumeric(5, 'abc', '>'));

        self::assertTrue(\SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::compareNumeric(10, 5, '>'));
        self::assertFalse(\SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::compareNumeric(5, 5, '>'));
        self::assertTrue(\SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::compareNumeric(5, 5, '>='));
        self::assertTrue(\SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::compareNumeric(5, 10, '<'));
        self::assertTrue(\SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::compareNumeric(5, 5, '<='));
        self::assertFalse(\SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::compareNumeric(5, 5, 'unknown'));
    }

    /**
     * `matchesBool` coerces both sides before equality — pins
     * the symmetric coercion against mutants that skip one side.
     *
     * @return void
     */
    public function testMatchesBoolCoercesBothSidesSymmetrically(): void
    {
        $cls = \SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::class;

        self::assertTrue($cls::matchesBool(true, 'true'));
        self::assertTrue($cls::matchesBool('1', 1));
        self::assertTrue($cls::matchesBool(false, 'no'));
        self::assertTrue($cls::matchesBool('anything-else', 0));
        self::assertFalse($cls::matchesBool(true, false));
        self::assertFalse($cls::matchesBool(false, true));
    }

    /**
     * `matchesCidr` handles exact-match, /0 mask, /32 mask, and
     * bad-input cases. Pins the `0 ? 0 : (-1 << (32 - $bits))`
     * ternary.
     *
     * @return void
     */
    public function testMatchesCidrMatrix(): void
    {
        $cls = \SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::class;

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
     * `compareTimes` uses the `<` / `>` comparator; anything else
     * returns false. Pins the default-arm `false` against
     * FalseValue / MatchArmRemoval mutants.
     *
     * @return void
     */
    public function testCompareTimesDefaultArmReturnsFalse(): void
    {
        $cls = \SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::class;

        self::assertTrue($cls::compareTimes('2026-01-01', '2026-06-01', '<'));
        self::assertTrue($cls::compareTimes('2026-06-01', '2026-01-01', '>'));
        self::assertFalse($cls::compareTimes('2026-01-01', '2026-06-01', '>'));
        self::assertFalse($cls::compareTimes('2026-06-01', '2026-01-01', '<'));

        // Default arm.
        self::assertFalse($cls::compareTimes('2026-01-01', '2026-06-01', '=='));
        self::assertFalse($cls::compareTimes('2026-01-01', '2026-06-01', 'unknown'));

        // Null timestamps fail closed.
        self::assertFalse($cls::compareTimes('not-a-time', '2026-06-01', '<'));
        self::assertFalse($cls::compareTimes('2026-01-01', 'not-a-time', '<'));
    }

    /**
     * `matchesBetween` requires both bounds; returns false on
     * missing operand keys, malformed operand, or out-of-range
     * values. Pins the `>=` and `<=` inclusive bounds.
     *
     * @return void
     */
    public function testMatchesBetweenRequiresBothBoundsAndInclusive(): void
    {
        $cls = \SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator::class;

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
     * Run a callable and assert it throws the expected exception
     * class with the expected message. Shared helper for the
     * `resolveEffect` / `resolveActions` branches.
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
     * `attachPolicy()` with a different expiry fires
     * `IdentityPolicyExpiryChanged`.
     *
     * @return void
     */
    public function testAttachPolicyFiresExpiryChangedWhenWindowMoves(): void
    {
        \Illuminate\Support\Facades\Event::fake(
            [\SineMacula\Laravel\Authorization\Events\IdentityPolicyExpiryChanged::class],
        );

        $policy = \SineMacula\Laravel\Authorization\Models\Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'policy-m',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->attachPolicy($policy, new \DateTimeImmutable('+1 hour'));
        $user->attachPolicy($policy, new \DateTimeImmutable('+2 hours'));

        \Illuminate\Support\Facades\Event::assertDispatchedTimes(
            \SineMacula\Laravel\Authorization\Events\IdentityPolicyExpiryChanged::class,
            1,
        );
    }
}
