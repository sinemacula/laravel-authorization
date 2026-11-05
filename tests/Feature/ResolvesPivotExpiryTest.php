<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\ResolvesPivotExpiry;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the grant service accessor `ResolvesPivotExpiry` gives the
 * identity traits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ResolvesPivotExpiry::class)]
final class ResolvesPivotExpiryTest extends TestCase
{
    use ActsAsTenant;

    /**
     * Allow lazy loading again.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Model::preventLazyLoading(false);

        parent::tearDown();
    }

    /**
     * A grant counts only in its scope: "admin in A, viewer in B" for one
     * identity and two platform roles, while a platform-wide grant counts in
     * every tenant and with none (AUTHZ-5.1, AUTHZ-5.7).
     *
     * @return void
     */
    public function testGrantsCountOnlyInTheirScope(): void
    {
        $tenantA = self::createTenant('tenant-a');
        $tenantB = self::createTenant('tenant-b');
        $user    = StubIdentity::query()->create(['id' => 'user-1']);

        Role::query()->create(['name' => 'admin']);
        Role::query()->create(['name' => 'viewer']);
        Role::query()->create(['name' => 'member']);

        $user->assignRole('admin', null, $tenantA);
        $user->assignRole('viewer', null, $tenantB);
        $user->assignRole('member');

        $this->actAsTenant($tenantA);
        self::assertEqualsCanonicalizing(['admin', 'member'], $user->getRoles());
        self::assertTrue(self::reread($user)->hasRole('admin'));

        $this->actAsTenant($tenantB);
        self::assertEqualsCanonicalizing(['viewer', 'member'], $user->getRoles());
        self::assertFalse(self::reread($user)->hasRole('admin'));

        $this->actAsTenant(null);
        self::assertSame(['member'], $user->getRoles());
    }

    /**
     * An identity hydrated with others resolves its roles, permissions and
     * policies under `Model::preventLazyLoading()`, with several roles and a
     * parent among them, because every grant is loaded explicitly.
     *
     * @return void
     */
    public function testResolvesWithoutLazyLoading(): void
    {
        $parent = Role::query()->create(['name' => 'reader']);
        $writer = Role::query()->create(['name' => 'writer', 'parent_id' => $parent->id]);
        $editor = Role::query()->create(['name' => 'editor']);

        $parent->permissions()->attach(Permission::query()->create(['name' => 'posts:read'])->id);
        $writer->permissions()->attach(Permission::query()->create(['name' => 'posts:write'])->id);

        $user = StubIdentity::query()->create(['id' => 'user-1']);
        $user->assignRole($writer);
        $user->assignRole($editor);
        $user->givePermission(Permission::query()->create(['name' => 'posts:publish']));
        $user->attachPolicy(Policy::query()->create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]));

        StubIdentity::query()->create(['id' => 'user-2']);

        Model::preventLazyLoading();

        $hydrated = StubIdentity::query()->orderBy('id')->get()->firstOrFail();

        self::assertTrue($hydrated->hasPermission('posts:read'));
        self::assertEqualsCanonicalizing(['posts:publish', 'posts:read', 'posts:write'], $hydrated->getPermissions());
        self::assertTrue($hydrated->hasRole('editor'));
        self::assertEqualsCanonicalizing(['editor', 'writer'], $hydrated->getRoles());
        self::assertSame(['readers'], \array_map(static fn ($policy): string => $policy->name, $hydrated->getPolicies()));
    }

    /**
     * The identity traits write through the grant service the container binds.
     *
     * @return void
     */
    public function testWritesThroughTheBoundGrantService(): void
    {
        $role = Role::query()->create(['name' => 'editor']);

        StubIdentity::query()->create(['id' => 'user-1'])->assignRole($role);

        self::assertSame([$role->id], DB::table('authorizable_roles')->pluck('role_id')->all());
    }

    /**
     * Without the grant service bound, a write is refused rather than lost.
     *
     * @return void
     */
    public function testRefusesAWriteWithoutTheGrantService(): void
    {
        $user = StubIdentity::query()->create(['id' => 'user-1']);

        unset($this->app[GrantService::class]);

        $this->expectExceptionObject(new \LogicException('The authorization grant service is not bound; register the package\'s service provider.'));

        $user->assignRole('editor');
    }

    /**
     * Read the identity afresh, as a later request would.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function reread(StubIdentity $user): StubIdentity
    {
        return StubIdentity::query()->whereKey($user->getKey())->firstOrFail();
    }
}
