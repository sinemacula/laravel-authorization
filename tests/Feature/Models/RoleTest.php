<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Feature tests for the string casts on the shipped `Role` model, and the
 * policies it takes as a grantee.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Role::class)]
final class RoleTest extends StringCastsTestCase
{
    /**
     * A role takes policies as a grantee, through the policies table with the
     * role as the grantee.
     *
     * @return void
     */
    public function testARoleTakesPolicies(): void
    {
        $role   = Role::create(['name' => 'editor']);
        $policy = Policy::create(['name' => 'editors', 'document' => ['version' => 1, 'statements' => []]]);

        $role->attachPolicy($policy);

        self::assertInstanceOf(SupportsPolicies::class, $role);
        self::assertSame([$policy->id], $role->policies()->pluck('policies.id')->all());
        self::assertSame([$role->getMorphClass()], DB::table('authorizable_policies')->pluck('authorizable_type')->all());
    }

    /**
     * Create an instance of the model under test.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    protected static function newModel(): Model
    {
        return new Role;
    }

    /**
     * Return the model's fillable string columns.
     *
     * @return list<string>
     */
    #[\Override]
    protected static function stringColumns(): array
    {
        return ['name', 'guard', 'description', 'parent_id', 'tenant_type', 'tenant_id'];
    }
}
