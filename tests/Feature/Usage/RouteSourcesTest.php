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

        self::assertEqualsCanonicalizing(['posts:delete', 'posts:edit'], \array_keys($routes));
        $delete = ['role_grant ann [editor] editor', 'role_inherited ann [editor>admin] admin', 'role_permission ann [editor>admin] posts:delete'];
        $edit   = [
            'permission_grant ann posts:edit',
            'role_grant ann [editor] editor',
            'role_permission ann [editor] posts:edit',
            'role_inherited ann [editor>admin] admin',
            'role_permission ann [editor>admin] posts:edit',
        ];

        self::assertSame(self::rowKeys($ann, $delete), self::keysOf($routes['posts:delete']));
        self::assertSame(self::rowKeys($ann, $edit), self::keysOf($routes['posts:edit']));

        $created = DB::table('authorizable_permissions')->value('created_at');

        self::assertSame(Carbon::parse(\is_string($created) ? $created : '', 'UTC')->getTimestamp(), $routes['posts:edit'][0]->grant->createdAt);
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

        self::assertSame(self::rowKeys($ann, ['policy_attachment ann deny-own']), self::keysOf($routes[Reference::of($own)->id]));
        self::assertSame(self::rowKeys($ann, $throughRole), self::keysOf($routes[Reference::of($role)->id]));
        self::assertNull(RouteSources::policies($ann, [], new EloquentCollection([$admin]), new InheritedPolicies(stable: false)));
        self::assertNull(GrantResolver::policies($ann->policies(), new ResolutionPins, RolePolicies::heldBy($ann))->routes);
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
