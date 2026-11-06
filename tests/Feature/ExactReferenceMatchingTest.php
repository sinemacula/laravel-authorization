<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Database\ExactReferences;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the exact matching of references in SQL: a tenant, grantee
 * or resource whose key differs from another's only by case or a trailing space
 * is a different one to a check and to the unique keys, on every database, as
 * it is to the package's comparisons in PHP.
 *
 * The keys that differ only so are never both written to the test's own tenant
 * and identity tables, whose keys MySQL compares through their case-insensitive
 * collation; a tenant or grantee the test does not store is an unsaved model
 * with its key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversNothing]
final class ExactReferenceMatchingTest extends TestCase
{
    use ActsAsTenant;

    /** @var string The key every stored tenant, grantee and record has. */
    private const string KEY = 'org';

    /** @var list<string> The tables that carry reference columns. */
    private const array TABLES = [
        'roles',
        'permissions',
        'policies',
        'authorizable_roles',
        'authorizable_permissions',
        'authorizable_policies',
        'resource_policies',
        'authorizable_boundaries',
        'guardrails',
    ];

    /**
     * The keys that differ from the stored key only by case or by a trailing
     * space.
     *
     * @return iterable<string, array{string}>
     */
    public static function nearTwins(): iterable
    {
        yield 'case' => ['ORG'];
        yield 'trailing space' => ['org '];
    }

    /**
     * A grant made in a tenant does not reach a tenant whose key differs only
     * by case or a trailing space, and still reaches its own.
     *
     * @param  string  $twin
     * @return void
     */
    #[DataProvider('nearTwins')]
    public function testAGrantInATenantDoesNotReachItsNearTwin(string $twin): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        Role::create(['name' => 'editor'])->givePermission(Permission::create(['name' => 'posts:edit']));
        $user->assignRole('editor', null, self::tenant(self::KEY));

        self::assertFalse($this->canIn($user, self::tenant($twin), 'posts:edit'));
        self::assertTrue($this->canIn($user, self::tenant(self::KEY), 'posts:edit'));
    }

    /**
     * A grant made to a grantee does not reach a grantee whose key differs only
     * by case or a trailing space.
     *
     * @param  string  $twin
     * @return void
     */
    #[DataProvider('nearTwins')]
    public function testAGrantToAGranteeDoesNotReachItsNearTwin(string $twin): void
    {
        $user = StubIdentity::create(['id' => self::KEY]);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        self::assertFalse(Authorization::for(self::unsavedIdentity($twin))->can('posts:edit'));
        self::assertTrue(Authorization::for($user)->can('posts:edit'));
    }

    /**
     * The grant table's unique key holds a grant in a tenant and in each of its
     * near twins as different rows, and a grant to a grantee and to each of its
     * near twins likewise.
     *
     * @return void
     */
    public function testTheGrantKeyKeepsNearTwinsApart(): void
    {
        $role = Role::create(['name' => 'editor']);
        $user = StubIdentity::create(['id' => self::KEY]);

        foreach ([self::KEY, 'ORG', 'org '] as $key) {
            $user->assignRole($role, null, self::tenant($key));
            self::unsavedIdentity($key)->assignRole($role);
        }

        $rows = DB::table('authorizable_roles')->get(['authorizable_id', 'tenant_id'])->map(
            static fn (object $row): string => self::string($row->authorizable_id ?? null) . '|' . self::string($row->tenant_id ?? null),
        );

        self::assertSame(['ORG|', 'org |', 'org|', 'org|ORG', 'org|org', 'org|org '], self::sorted($rows->all()));
    }

    /**
     * Two tenants whose keys differ only by case or a trailing space may each
     * own a role of one name, and each sees only its own.
     *
     * @return void
     */
    public function testNearTwinTenantsOwnRolesApart(): void
    {
        foreach ([self::KEY, 'ORG', 'org '] as $key) {
            Role::create(['name' => 'manager', 'guard' => 'web', 'tenant_type' => self::tenant($key)->getMorphClass(), 'tenant_id' => $key]);
        }

        $this->actAsTenant(self::tenant('ORG'));

        self::assertSame(['ORG'], Role::query()->where('name', 'manager')->pluck('tenant_id')->all());
        self::assertSame(3, Role::query()->withoutGlobalScopes()->where('name', 'manager')->count());
    }

    /**
     * A policy attached to a record does not reach a record whose key differs
     * only by case or a trailing space, and the attachment key holds an
     * attachment to each as a different row.
     *
     * @param  string  $twin
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('nearTwins')]
    public function testAResourcePolicyOnARecordDoesNotReachItsNearTwin(string $twin): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::policy('sharing', ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => [$user->getMorphClass() . ':user-1']]);

        self::assertSame(GrantOutcome::GRANTED, self::resourcePolicies()->attach($policy, ['posts', self::KEY]));

        self::assertFalse(Authorization::for($user)->can('posts:read', ResourceReference::record('posts', $twin)));
        self::assertTrue(Authorization::for($user)->can('posts:read', ResourceReference::record('posts', self::KEY)));

        self::assertSame(GrantOutcome::GRANTED, self::resourcePolicies()->attach($policy, ['posts', $twin]));
        self::assertSame(2, DB::table('resource_policies')->count());
    }

    /**
     * A guardrail set on a tenant does not cap a tenant whose key differs only
     * by case or a trailing space, and still caps its own.
     *
     * @param  string  $twin
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('nearTwins')]
    public function testAGuardrailOnATenantDoesNotCapItsNearTwin(string $twin): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $actor = StubIdentity::create(['id' => 'guardrail-admin']);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        $actor->givePermission(Permission::create(['name' => PackagePermissions::GUARDRAILS_MANAGE]));

        $guardrails = GuardrailService::instance();

        self::assertInstanceOf(GuardrailService::class, $guardrails);

        $guardrails->set(self::policy('read-only', ['effect' => 'allow', 'actions' => ['posts:read']]), self::tenant(self::KEY), $actor);

        self::assertTrue($this->canIn($user, self::tenant($twin), 'posts:edit'));
        self::assertFalse($this->canIn($user, self::tenant(self::KEY), 'posts:edit'));
    }

    /**
     * A boundary set in a tenant does not cap a tenant whose key differs only
     * by case or a trailing space, nor a grantee whose key does.
     *
     * @param  string  $twin
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('nearTwins')]
    public function testABoundaryDoesNotCapANearTwin(string $twin): void
    {
        $user = StubIdentity::create(['id' => self::KEY]);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        $boundaries = BoundaryService::instance();

        self::assertInstanceOf(BoundaryService::class, $boundaries);

        $readOnly = self::policy('read-only', ['effect' => 'allow', 'actions' => ['posts:read']]);

        $boundaries->set($user, $readOnly, self::tenant(self::KEY));
        $boundaries->set(new Reference($user->getMorphClass(), $twin), $readOnly);

        self::assertTrue($this->canIn($user, self::tenant($twin), 'posts:edit'));
        self::assertFalse($this->canIn($user, self::tenant(self::KEY), 'posts:edit'));
    }

    /**
     * On MySQL every reference column of the package's tables compares its
     * exact bytes, and the other columns keep the table's collation.
     *
     * @return void
     */
    public function testEveryReferenceColumnIsByteExactOnMySql(): void
    {
        if (DB::connection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL compares a column through a collation that folds case.');
        }

        $columns = DB::table('information_schema.columns')
            ->where('table_schema', DB::connection()->getDatabaseName())
            ->whereIn('table_name', self::TABLES)
            ->whereNotNull('collation_name')
            ->get(['table_name as table', 'column_name as column', 'collation_name as collation']);

        $references = 0;

        foreach ($columns as $column) {
            $name  = self::string($column->column ?? null);
            $exact = \in_array($name, ExactReferences::COLUMNS, true);

            self::assertSame($exact, $column->collation === ExactReferences::COLLATION, self::string($column->table ?? null) . '.' . $name);

            $references += (int) $exact;
        }

        self::assertSame(44, $references);
    }

    /**
     * Determine whether the user may perform the action with the given tenant
     * active.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @param  string  $action
     * @return bool
     */
    private function canIn(StubIdentity $user, StubTenant $tenant, string $action): bool
    {
        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenant));
        $this->app?->forgetInstance(ResolvedTenant::class);

        return Authorization::for($user)->can($action);
    }

    /**
     * Return an unsaved tenant with the given key.
     *
     * @param  string  $key
     * @return \Tests\Feature\Stubs\StubTenant
     */
    private static function tenant(string $key): StubTenant
    {
        return new StubTenant(['id' => $key, 'name' => $key]);
    }

    /**
     * Return an identity with the given key that the test does not store, as
     * though it had been read from the database.
     *
     * @param  string  $key
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function unsavedIdentity(string $key): StubIdentity
    {
        return (new StubIdentity)->newInstance(['id' => $key], true);
    }

    /**
     * Create a managed policy of the one statement.
     *
     * @param  string  $name
     * @param  array<string, mixed>  $statement
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, array $statement): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [$statement]]]);
    }

    /**
     * Return the resource policy service, as the container binds it.
     *
     * @return \SineMacula\Laravel\Authorization\Services\ResourcePolicyService
     */
    private static function resourcePolicies(): ResourcePolicyService
    {
        $service = ResourcePolicyService::instance();

        self::assertInstanceOf(ResourcePolicyService::class, $service);

        return $service;
    }

    /**
     * Return the value as a string, or an empty string for anything else.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function string(mixed $value): string
    {
        return \is_string($value) ? $value : '';
    }

    /**
     * Sort the strings by their bytes.
     *
     * @param  array<int, mixed>  $values
     * @return list<string>
     */
    private static function sorted(array $values): array
    {
        $strings = \array_map(self::string(...), \array_values($values));

        \sort($strings, \SORT_STRING);

        return $strings;
    }
}
