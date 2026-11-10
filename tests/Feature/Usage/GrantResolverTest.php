<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Resolvers\GrantResolver;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RolePolicies;
use Tests\Concerns\ReviewsAccess;
use Tests\Fixtures\Usage\PinningStore;
use Tests\TestCase;

/**
 * Feature tests for the grant resolver while grant usage is tracked: a routed
 * resolution finds the same permissions and policies as any other, in the same
 * number of queries, with the routes behind them, and says none when the
 * hierarchy moved while it ran.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantResolver::class)]
final class GrantResolverTest extends TestCase
{
    use ReviewsAccess;

    /**
     * A routed resolution finds what any other does, in as many queries, and
     * alone keeps routes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoutedResolutionCostsWhatAnyOtherDoes(): void
    {
        $admin  = self::role('admin');
        $editor = self::role('editor', $admin);
        $ann    = self::identity('ann');

        $admin->givePermissionTo(self::permission('posts:read'));
        self::grants()->attachPolicy($admin, self::policy('no-delete'));
        self::grants()->attachPolicy($ann, self::policy('no-delete-own'));
        self::grants()->grantPermission($ann, self::permission('posts:write'));
        self::grants()->grantRole($ann, $editor);

        $resolve = static fn (bool $isRouting): array => [
            GrantResolver::permissions($ann->permissions(), $ann->roles(), new ResolutionPins(null, $isRouting)),
            GrantResolver::policies($ann->policies(), new ResolutionPins(null, $isRouting), RolePolicies::heldBy($ann)),
        ];

        [$plain, $plainQueries]   = self::counted(static fn (): array => $resolve(false));
        [$routed, $routedQueries] = self::counted(static fn (): array => $resolve(true));

        self::assertSame($plainQueries, $routedQueries);
        self::assertSame($plain[0]->value, $routed[0]->value);
        self::assertEquals($plain[1]->value, $routed[1]->value);
        self::assertSame([null, null], [$plain[0]->routes, $plain[1]->routes]);
        self::assertEqualsCanonicalizing(['posts:read', 'posts:write'], $routed[0]->routes?->names() ?? []);
        self::assertCount(2, $routed[1]->routes?->names() ?? []);
    }

    /**
     * A routed resolution whose hierarchy moved while it ran says no routes,
     * and is not stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMovedHierarchySaysNoRoutes(): void
    {
        $parent = self::role('publisher');
        $role   = self::role('editor');
        $ann    = self::identity('ann');

        $parent->givePermissionTo(self::permission('posts:publish'));
        self::grants()->grantRole($ann, $role);

        $moved = false;
        $key   = 'authz:version:role:' . Reference::of($role)->id;
        $store = new VersionedStore(new Repository(new PinningStore(static function (array $keys) use (&$moved, $key, $role, $parent): void {
            if ($moved || !\in_array($key, $keys, true)) {
                return;
            }

            $moved = true;

            DB::table('roles')->where('id', $role->getKey())->update(['parent_id' => $parent->getKey()]);
        })), 'authz');

        $resolution = GrantResolver::permissions($ann->permissions(), $ann->roles(), new ResolutionPins($store, true));

        self::assertSame(['posts:publish'], $resolution->value);
        self::assertFalse($resolution->stable);
        self::assertNull($resolution->routes);
    }

    /**
     * Return what the callback returns and how many queries it ran.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $callback
     * @return array{TResult, int}
     */
    private static function counted(\Closure $callback): array
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $result  = $callback();
        $queries = \count(DB::getQueryLog());

        DB::disableQueryLog();

        return [$result, $queries];
    }
}
