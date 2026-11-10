<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Resolvers\GrantResolver;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\InheritedPolicies;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RolePolicies;
use SineMacula\Laravel\Authorization\Usage\GrantRoute;
use SineMacula\Laravel\Authorization\Usage\GrantUsageKey;
use SineMacula\Laravel\Authorization\Usage\RouteSources;
use Tests\Concerns\ReviewsAccess;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the routes behind what a grantee's resolution finds while
 * grant usage is tracked: each permission and policy by every live route that
 * gives it, the same routes, by the same keys, an access review lists, each
 * with its stored grant's creation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RouteSources::class)]
final class RouteSourcesTest extends TestCase
{
    use ReviewsAccess;

    /**
     * Each permission is given by its direct grant and by each role of a held
     * role's chain carrying it, with the role granted and the ancestor reached,
     * by the keys the review lists.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachPermissionIsGivenByEveryRoute(): void
    {
        $admin  = self::role('admin');
        $editor = self::role('editor', $admin);
        $ann    = self::identity('ann');

        $edit = self::permission('posts:edit');

        $admin->givePermissionTo(self::permission('posts:delete'));
        $editor->givePermissionTo($edit);
        $admin->givePermissionTo($edit);

        self::grants()->grantRole($ann, $editor);
        self::grants()->grantPermission($ann, $edit);

        $resolution = GrantResolver::permissions($ann->permissions(), $ann->roles(), new ResolutionPins(null, true));
        $routes     = $resolution->routes ?? self::fail('No routes were kept.');

        self::assertEqualsCanonicalizing(['posts:delete', 'posts:edit'], $routes->names());
        $delete = ['role_grant ann [editor] editor', 'role_inherited ann [editor>admin] admin', 'role_permission ann [editor>admin] posts:delete'];
        $edit   = [
            'permission_grant ann posts:edit',
            'role_grant ann [editor] editor',
            'role_permission ann [editor] posts:edit',
            'role_inherited ann [editor>admin] admin',
            'role_permission ann [editor>admin] posts:edit',
        ];

        self::assertSame(self::rowKeys($ann, $delete), self::keysOf($routes->routesFor('posts:delete')));
        self::assertSame(self::rowKeys($ann, $edit), self::keysOf($routes->routesFor('posts:edit')));
        self::assertSame([], $routes->routesFor('posts:read'));
        self::assertSame(self::createdAt('authorizable_permissions'), $routes->routesFor('posts:edit')[0]->grant->createdAt);
    }

    /**
     * Each policy is given by its attachment to the grantee and by each role of
     * a held role's chain it is attached to, by the keys the review lists; a
     * role resolution whose hierarchy moved can say none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachPolicyIsGivenByEveryRoute(): void
    {
        $admin  = self::role('admin');
        $editor = self::role('editor', $admin);
        $ann    = self::identity('ann');
        $own    = self::policy('deny-own');
        $role   = self::policy('deny-admin');

        self::grants()->attachPolicy($admin, $role);
        self::grants()->attachPolicy($ann, $own);
        self::grants()->grantRole($ann, $editor);

        $resolution = GrantResolver::policies($ann->policies(), new ResolutionPins(null, true), RolePolicies::heldBy($ann));
        $routes     = $resolution->routes ?? self::fail('No routes were kept.');

        $throughRole = ['role_grant ann [editor] editor', 'role_inherited ann [editor>admin] admin', 'role_policy ann [editor>admin] deny-admin'];

        self::assertSame(self::rowKeys($ann, ['policy_attachment ann deny-own']), self::keysOf($routes->routesFor(Reference::of($own)->id)));
        self::assertSame(self::rowKeys($ann, $throughRole), self::keysOf($routes->routesFor(Reference::of($role)->id)));
        self::assertSame(self::createdAt('authorizable_policies'), $routes->routesFor(Reference::of($own)->id)[0]->grant->createdAt);
        self::assertNull(RouteSources::policies($ann, [], new EloquentCollection([$admin]), new InheritedPolicies(stable: false)));
        self::assertNull(GrantResolver::policies($ann->policies(), new ResolutionPins, RolePolicies::heldBy($ann))->routes);
    }

    /**
     * Every route of a grant made in a tenant for an application carries the
     * tenant and application it was stored with, a role's routes and a policy
     * attachment's included, by the keys the review lists for those grants.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRoutesCarryTheScopeTheirGrantsWereMadeIn(): void
    {
        $this->tree();

        $org    = self::tenant('org1');
        $ann    = self::identity('ann');
        $editor = self::role('editor');
        $policy = self::policy('deny-own');

        $editor->givePermissionTo(self::permission('posts:edit'));

        self::grants()->grantPermission($ann, self::permission('posts:read'), null, null, $org, true, 'web');
        self::grants()->grantRole($ann, $editor, null, null, $org, true, 'web');
        self::grants()->attachPolicy($ann, $policy, null, null, $org, true, 'web');

        [$permissions, $policies] = TenantScope::within($org, 'web', static fn (): array => [
            GrantResolver::permissions($ann->permissions(), $ann->roles(), new ResolutionPins(null, true))->routes,
            GrantResolver::policies($ann->policies(), new ResolutionPins(null, true), RolePolicies::heldBy($ann))->routes,
        ]);

        self::assertNotNull($permissions);
        self::assertNotNull($policies);

        $routes = [...$permissions->routesFor('posts:read'), ...$permissions->routesFor('posts:edit'), ...$policies->routesFor(Reference::of($policy)->id)];
        $scope  = static fn (GrantRoute $route): string => \implode('|', [$route->grant->tenantType, $route->grant->tenantId, $route->grant->application]);
        $scopes = \array_unique(\array_map($scope, $routes));

        self::assertSame(['tenant|org1|web'], \array_values($scopes));
        self::assertSame(
            self::rowKeys($ann, ['permission_grant ann posts:read', 'role_grant ann [editor] editor', 'role_permission ann [editor] posts:edit', 'policy_attachment ann deny-own']),
            self::keysOf($routes),
        );
    }

    /**
     * A role's grant, and the ancestor it reaches, are kept once however many
     * permissions the role carries, each permission referencing them, so the
     * routes kept grow with the grants and the permissions, never with both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolesRoutesAreKeptOnce(): void
    {
        $admin  = self::role('admin');
        $editor = self::role('editor', $admin);
        $ann    = self::identity('ann');

        for ($index = 0; $index < 20; $index++) {
            $admin->givePermissionTo(self::permission('posts:p' . $index));
        }

        self::grants()->grantRole($ann, $editor);

        $routes = GrantResolver::permissions($ann->permissions(), $ann->roles(), new ResolutionPins(null, true))->routes ?? self::fail('No routes were kept.');

        self::assertCount(1, $routes->grants);
        self::assertCount(22, $routes->routes);
        self::assertCount(20, $routes->names());
        self::assertSame($routes->routesFor('posts:p0')[1]->key, $routes->routesFor('posts:p19')[1]->key);
    }

    /**
     * Return the key of each route among the routes, each once, sorted.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>  $routes
     * @return list<string>
     */
    private static function keysOf(array $routes): array
    {
        $keys = \array_values(\array_unique(\array_map(static fn (GrantRoute $route): string => $route->key, $routes)));

        \sort($keys);

        return $keys;
    }

    /**
     * Return the creation of the only row of the grant table, as a UTC
     * timestamp.
     *
     * @param  string  $table
     * @return int
     */
    private static function createdAt(string $table): int
    {
        $created = DB::table($table)->value('created_at');

        return Carbon::parse(\is_string($created) ? $created : '', 'UTC')->getTimestamp();
    }

    /**
     * Return the usage key of each of the subject's holdings the review lists
     * as described, sorted.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $subject
     * @param  list<string>  $described
     * @return list<string>
     */
    private static function rowKeys(StubIdentity $subject, array $described): array
    {
        $query  = ReviewQuery::holdings(new Subject($subject, $subject), ReviewScope::everywhere());
        $result = self::trusted($query);
        $keys   = [];

        foreach ($result->rows as $row) {
            if (!\in_array(self::describe($row), $described, true)) {
                continue;
            }

            $keys[] = GrantUsageKey::ofRow($row);
        }

        self::assertCount(\count($described), $keys);

        \sort($keys);

        return $keys;
    }
}
