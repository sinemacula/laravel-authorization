<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationNameException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\PermissionObserver;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Traits\ManagesPermissions;
use SineMacula\Laravel\Authorization\Traits\ValidatesAuthorizationName;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the wildcard-permission bundle.
 *
 * - `HasPermissions::hasPermission()` and `Role::hasPermission()`
 *   treat held names as `fnmatch` patterns: a held `posts:*`
 *   satisfies an asked `posts:create`, a held `*:*` satisfies
 *   anything (the super-admin bypass). The reverse direction does
 *   not match.
 * - `Statement::matchesAction()` / `matchesResource()` compare
 *   patterns with `FNM_NOESCAPE`, so backslash-bearing resource
 *   identifiers (fully-qualified morph classes without an alias)
 *   match literally.
 * - `ValidatesAuthorizationName` rejects role and permission names
 *   that contain glob metacharacters or whitespace before the row
 *   hits the database, so `fnmatch` cannot be tricked by a
 *   malformed value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Role::class)]
#[CoversClass(RoleObserver::class)]
#[CoversClass(Permission::class)]
#[CoversClass(PermissionObserver::class)]
#[CoversClass(Statement::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(NullTenantResolver::class)]
#[CoversClass(ResolutionCacheContext::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
#[CoversTrait(HasRoleHierarchy::class)]
#[CoversTrait(ManagesPermissions::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversTrait(ValidatesAuthorizationName::class)]
final class WildcardPermissionTest extends TestCase
{
    /** Canonical asked action used across scenarios. */
    private const string ASKED_ACTION = 'posts:create';

    /**
     * An identity holding `posts:*` satisfies `hasPermission('posts:create')`.
     *
     * @return void
     */
    public function testHeldWildcardSatisfiesNarrowerAsk(): void
    {
        $user = $this->userHolding('posts:*');

        self::assertTrue($user->fresh()?->hasPermission(self::ASKED_ACTION));
    }

    /**
     * The wildcard does not cross the action prefix — a held
     * `posts:*` does not satisfy `users:create`.
     *
     * @return void
     */
    public function testHeldWildcardDoesNotMatchDifferentPrefix(): void
    {
        $user = $this->userHolding('posts:*');

        self::assertFalse($user->fresh()?->hasPermission('users:create'));
    }

    /**
     * The reverse direction does not match — holding the concrete
     * `posts:create` does not satisfy an asked `posts:*`.
     *
     * @return void
     */
    public function testHeldConcreteDoesNotSatisfyWildcardAsk(): void
    {
        $user = $this->userHolding(self::ASKED_ACTION);

        self::assertFalse($user->fresh()?->hasPermission('posts:*'));
    }

    /**
     * The super-admin principal holds `*:*` and satisfies every
     * concrete asked permission — including prefixes it has never
     * seen before.
     *
     * @return void
     */
    public function testSuperAdminWildcardSatisfiesEverything(): void
    {
        $user = $this->userHolding('*:*');

        $fresh = $user->fresh();

        self::assertNotNull($fresh);
        self::assertTrue($fresh->hasPermission(self::ASKED_ACTION));
        self::assertTrue($fresh->hasPermission('users:delete'));
        self::assertTrue($fresh->hasPermission('billing:export'));
    }

    /**
     * A role holding `posts:*` also answers `hasPermission` with
     * the wildcard semantics, so the check is symmetrical on both
     * sides of the RBAC edge.
     *
     * @return void
     */
    public function testRoleHasPermissionWildcardMatch(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:*',
            'guard_name' => 'web',
        ]);

        $role->givePermission('posts:*');

        $fresh = $role->fresh();

        self::assertNotNull($fresh);
        self::assertTrue($fresh->hasPermission(self::ASKED_ACTION));
        self::assertFalse($fresh->hasPermission('users:create'));
    }

    /**
     * Wildcard matching is inherited through roles — a role
     * holding `posts:*` flows through to the identity.
     *
     * @return void
     */
    public function testIdentityInheritsRoleWildcard(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:*',
            'guard_name' => 'web',
        ]);
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);
        $role->givePermission('posts:*');

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('editor');

        self::assertTrue($user->fresh()?->hasPermission(self::ASKED_ACTION));
    }

    /**
     * Statement resource matching treats backslashes literally —
     * an FQN-shaped resource identifier reaches the matcher unescaped.
     *
     * @return void
     */
    public function testStatementMatchesBackslashBearingResourceLiterally(): void
    {
        // Keep an empty morph map so a Statement's resource pattern
        // is compared against a raw FQN-like string. Any prior test
        // that registered an alias has been torn down.
        Relation::morphMap([], false);

        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => [self::ASKED_ACTION],
            'resources' => ['App\Models\Post:42'],
        ]);

        self::assertTrue($statement->matches(self::ASKED_ACTION, 'App\Models\Post:42'));
        self::assertFalse($statement->matches(self::ASKED_ACTION, 'App\Models\Post:99'));
    }

    /**
     * Statement action matching also accepts backslash-bearing
     * patterns literally.
     *
     * @return void
     */
    public function testStatementMatchesBackslashBearingActionLiterally(): void
    {
        $statement = Statement::fromArray([
            'effect'  => 'allow',
            'actions' => ['App\Jobs\Ping'],
        ]);

        self::assertTrue($statement->matches('App\Jobs\Ping'));
    }

    /**
     * Invalid name samples for the data provider.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function invalidPermissionNames(): iterable
    {
        yield 'whitespace' => ['has space'];
        yield 'empty' => [''];
        yield 'question-mark' => ['posts:?'];
        yield 'square-brackets' => ['posts:[abc]'];
        yield 'curly-brackets' => ['posts:{a,b}'];
        yield 'backslash' => ['App\Models\Post'];
        yield 'forward-slash' => ['posts/create'];
    }

    /**
     * Every name the evaluator walks is safe — metacharacters and
     * whitespace are rejected at save time so `fnmatch` cannot be
     * tricked into matching through a malformed name.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('invalidPermissionNames')]
    public function testInvalidPermissionNameIsRejected(string $name): void
    {
        $this->expectException(InvalidAuthorizationNameException::class);

        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => 'web',
        ]);
    }

    /**
     * The same rule applies to role names.
     *
     * @return void
     */
    public function testInvalidRoleNameIsRejected(): void
    {
        $this->expectException(InvalidAuthorizationNameException::class);

        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'has space',
            'guard_name' => 'web',
        ]);
    }

    /**
     * Valid name samples for the data provider.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function validPermissionNames(): iterable
    {
        yield 'colon-separated' => ['posts:create'];
        yield 'wildcard' => ['posts:*'];
        yield 'super-admin' => ['*:*'];
        yield 'hyphenated' => ['platform-admin'];
        yield 'underscored' => ['a_b_c'];
        yield 'numeric' => ['v2:post:42'];
    }

    /**
     * The allowed character class covers the common permission
     * shapes — action strings, hyphenated names, underscores, and
     * wildcards.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('validPermissionNames')]
    public function testValidPermissionNameIsAccepted(string $name): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => 'web',
        ]);

        self::assertSame($name, $permission->name);
    }

    /**
     * Attach a single permission (created if missing) to a fresh
     * authorizable and return the identity.
     *
     * @param  string  $name
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function userHolding(string $name): StubIdentity
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission($name);

        return $user;
    }
}
