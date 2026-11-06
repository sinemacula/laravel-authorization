<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature tests for the limit to the grants that hold in an application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantApplications::class)]
final class GrantApplicationsTest extends TestCase
{
    /**
     * In an application, the grants for every application and those for it
     * count, grouped so the limit narrows the query; without one, only the
     * grants for every application.
     *
     * @return void
     */
    public function testOnlyGrantsForEveryApplicationOrForItCount(): void
    {
        $role = Role::query()->create(['name' => 'editor']);

        foreach (['every' => null, 'admin' => 'admin', 'mobile' => 'mobile', 'other' => null] as $grantee => $application) {
            DB::table('authorizable_roles')->insert(['role_id' => $role->id, 'authorizable_type' => 'stub_identity', 'authorizable_id' => $grantee, 'application' => $application]);
        }

        $query = DB::table('authorizable_roles')->where('authorizable_id', '!=', 'other');

        self::assertSame($query, GrantApplications::only($query, 'authorizable_roles', 'admin'));
        self::assertEqualsCanonicalizing(['every', 'admin'], $query->pluck('authorizable_id')->all());
        self::assertEqualsCanonicalizing(['every', 'other'], GrantApplications::only(DB::table('authorizable_roles'), 'authorizable_roles', null)->pluck('authorizable_id')->all());
    }
}
