<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\Support\Definitions;
use Tests\Feature\Stubs\CustomRole;
use Tests\TestCase;

/**
 * Feature tests for the configured definition models a review names its targets
 * by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Definitions::class)]
final class DefinitionsTest extends TestCase
{
    /**
     * Each kind of grant is named by its configured model's morph type, its
     * table and key, and a type that is none of theirs is no kind.
     *
     * @return void
     */
    public function testEachKindIsNamedByItsConfiguredModel(): void
    {
        self::assertSame(
            [(new Role)->getMorphClass(), (new Permission)->getMorphClass(), (new Policy)->getMorphClass()],
            \array_map(Definitions::morph(...), GrantTarget::cases()),
        );
        self::assertSame(GrantTarget::ROLE, Definitions::kindOf((new Role)->getMorphClass()));
        self::assertSame(GrantTarget::PERMISSION, Definitions::kindOf((new Permission)->getMorphClass()));
        self::assertSame(GrantTarget::POLICY, Definitions::kindOf((new Policy)->getMorphClass()));
        self::assertNull(Definitions::kindOf('user'));
        self::assertSame(['roles', 'id'], Definitions::tableOf(GrantTarget::ROLE));
        self::assertSame(['permissions', 'id'], Definitions::tableOf(GrantTarget::PERMISSION));
        self::assertSame(['policies', 'id'], Definitions::tableOf(GrantTarget::POLICY));
        self::assertSame('role_permissions', Definitions::edges());

        config(['authorization.models.role' => CustomRole::class, 'authorization.tables.role_permissions' => 'custom_edges']);

        self::assertSame((new CustomRole)->getMorphClass(), Definitions::morph(GrantTarget::ROLE));
        self::assertSame(GrantTarget::ROLE, Definitions::kindOf((new CustomRole)->getMorphClass()));
        self::assertSame('custom_edges', Definitions::edges());
    }

    /**
     * Only a UUID could key a definition, and a definition's key is read as
     * text on the driver of the query, so it compares with a grantee key column
     * on every database.
     *
     * @return void
     */
    public function testADefinitionKeyIsAUuidReadAsText(): void
    {
        self::assertTrue(Definitions::isKey((string) Str::uuid()));
        self::assertTrue(Definitions::isKey(\strtoupper((string) Str::uuid())));
        self::assertFalse(Definitions::isKey('editor'));
        self::assertFalse(Definitions::isKey(''));

        $role  = new Role;
        $query = AuthorizationConnection::connection()->table('roles');
        $read  = Definitions::keyAsText($query, 'roles.id');

        $role->forceFill(['name' => 'keyed'])->save();

        $isPostgres = AuthorizationConnection::connection()->getDriverName() === 'pgsql';
        $texts      = AuthorizationConnection::connection()->table('roles')->selectRaw($read . ' as id_text')->pluck('id_text')->all();

        self::assertSame($isPostgres ? 'cast("roles"."id" as text)' : $query->getGrammar()->wrap('roles.id'), $read);
        self::assertSame([$role->getKey()], $texts);
    }
}
