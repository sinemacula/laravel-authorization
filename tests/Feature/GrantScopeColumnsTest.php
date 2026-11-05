<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\QueryException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the scope columns of the three grant tables and their
 * unique key: a target is granted to a grantee at most once per tenant and
 * application, with the platform (null tenant columns) and every application (a
 * null application) each counting as one scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversNothing]
final class GrantScopeColumnsTest extends TestCase
{
    /** @var string The grantee every row is written for. */
    private const string GRANTEE = 'c7a4b1f0-8d2e-4f6a-9b3c-5e1d0a2f4b6c';

    /** @var list<string> The columns every grant table carries. */
    private const array COLUMNS = [
        'authorizable_type',
        'authorizable_id',
        'tenant_type',
        'tenant_id',
        'include_subtree',
        'application',
        'expires_at',
        'granted_by_type',
        'granted_by_id',
        'created_at',
        'updated_at',
    ];

    /**
     * The three grant tables, each with the column naming its target.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function grantTables(): iterable
    {
        yield 'roles' => ['authorizable_roles', 'role_id'];
        yield 'permissions' => ['authorizable_permissions', 'permission_id'];
        yield 'policies' => ['authorizable_policies', 'policy_id'];
    }

    /**
     * Every grant table carries the grantee, the scope, the expiry, who made
     * the grant and when.
     *
     * @param  string  $table
     * @param  string  $target
     * @return void
     */
    #[DataProvider('grantTables')]
    public function testGrantTableCarriesTheScopeColumns(string $table, string $target): void
    {
        self::assertTrue(Schema::hasColumns($table, [$target, ...self::COLUMNS]));
    }

    /**
     * A grant written without a scope is platform-wide, for every application,
     * includes the subtree and names no grantor.
     *
     * @param  string  $table
     * @param  string  $target
     * @return void
     */
    #[DataProvider('grantTables')]
    public function testScopeColumnsDefaultToAPlatformWideGrant(string $table, string $target): void
    {
        DB::table($table)->insert([$target => $this->targetFor($target)] + self::grantee());

        $row = DB::table($table)->sole();

        self::assertNull($row->tenant_type);
        self::assertNull($row->tenant_id);
        self::assertNull($row->application);
        self::assertNull($row->granted_by_type);
        self::assertNull($row->granted_by_id);
        self::assertTrue((bool) $row->include_subtree);
    }

    /**
     * An expiry beyond 2038 is stored and read back, which a `timestamp` column
     * refuses on MySQL.
     *
     * @param  string  $table
     * @param  string  $target
     * @return void
     */
    #[DataProvider('grantTables')]
    public function testExpiryBeyond2038IsStored(string $table, string $target): void
    {
        DB::table($table)->insert([$target => $this->targetFor($target), 'expires_at' => '2099-12-31 23:59:59'] + self::grantee());

        /** @var string $expiresAt */
        $expiresAt = DB::table($table)->value('expires_at');

        self::assertSame('2099-12-31 23:59:59', Carbon::parse($expiresAt)->format('Y-m-d H:i:s'));
    }

    /**
     * The same target may be granted to the same grantee once per scope: the
     * platform, each tenant and each application.
     *
     * @param  string  $table
     * @param  string  $target
     * @return void
     */
    #[DataProvider('grantTables')]
    public function testATargetMayBeGrantedOncePerScope(string $table, string $target): void
    {
        $id = $this->targetFor($target);

        DB::table($table)->insert([
            [$target => $id] + self::scope(null, null, null) + self::grantee(),
            [$target => $id] + self::scope('tenant', 'tenant-a', null) + self::grantee(),
            [$target => $id] + self::scope('tenant', 'tenant-b', null) + self::grantee(),
            [$target => $id] + self::scope(null, null, 'admin') + self::grantee(),
            [$target => $id] + self::scope('tenant', 'tenant-a', 'admin') + self::grantee(),
        ]);

        self::assertSame(5, DB::table($table)->count());
    }

    /**
     * A second grant of the same target to the same grantee in the same scope
     * is refused, the platform-wide, every-application scope included.
     *
     * @param  string  $table
     * @param  string  $target
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('grantTables')]
    public function testASecondGrantInTheSameScopeIsRefused(string $table, string $target): void
    {
        $id = $this->targetFor($target);

        foreach ([self::scope(null, null, null), self::scope('tenant', 'tenant-a', 'admin')] as $scope) {
            DB::table($table)->insert([$target => $id] + $scope + self::grantee());

            $refused = false;

            try {
                DB::transaction(static fn (): bool => DB::table($table)->insert([$target => $id] + $scope + self::grantee()));
            } catch (QueryException) {
                $refused = true;
            }

            self::assertTrue($refused, (string) \json_encode($scope));
        }
    }

    /**
     * A grant made through the identity's relation keeps its timestamps and is
     * platform-wide.
     *
     * @return void
     */
    public function testARelationGrantKeepsItsTimestamps(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        try {
            $identity = StubIdentity::query()->create(['id' => self::GRANTEE]);
            $identity->assignRole(Role::query()->create(['name' => 'editor']));
        } finally {
            Carbon::setTestNow();
        }

        $row = DB::table('authorizable_roles')->sole();

        self::assertSame('2026-07-01 12:00:00', Carbon::parse((string) $row->created_at)->format('Y-m-d H:i:s'));
        self::assertSame('2026-07-01 12:00:00', Carbon::parse((string) $row->updated_at)->format('Y-m-d H:i:s'));
        self::assertNull($row->tenant_type);
        self::assertNull($row->application);
    }

    /**
     * Return the grantee columns.
     *
     * @return array{authorizable_type: string, authorizable_id: string}
     */
    private static function grantee(): array
    {
        return ['authorizable_type' => 'stub_identity', 'authorizable_id' => self::GRANTEE];
    }

    /**
     * Return the scope columns.
     *
     * @param  string|null  $tenantType
     * @param  string|null  $tenantId
     * @param  string|null  $application
     * @return array{tenant_type: string|null, tenant_id: string|null, application: string|null}
     */
    private static function scope(?string $tenantType, ?string $tenantId, ?string $application): array
    {
        return ['tenant_type' => $tenantType, 'tenant_id' => $tenantId, 'application' => $application];
    }

    /**
     * Create the row the given target column points at and return its id.
     *
     * @param  string  $target
     * @return string
     */
    private function targetFor(string $target): string
    {
        $model = match ($target) {
            'role_id'       => Role::query()->create(['name' => 'editor']),
            'permission_id' => Permission::query()->create(['name' => 'posts:edit']),
            default         => Policy::query()->create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]),
        };

        /** @var string */
        return $model->getKey();
    }
}
