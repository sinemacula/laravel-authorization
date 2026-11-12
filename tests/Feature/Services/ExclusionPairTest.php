<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Exceptions\InvalidRoleExclusionException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\ExclusionPair;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\CatchesRefusals;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `ExclusionPair`: two roles as a pair, in its canonical
 * order, and who owns it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExclusionPair::class)]
final class ExclusionPairTest extends TestCase
{
    use CatchesRefusals;

    /**
     * The pair holds its roles with the lower key first, whichever order they
     * are given in, and refers to them in that order.
     *
     * @return void
     */
    public function testHoldsItsRolesInTheirCanonicalOrder(): void
    {
        $one   = Role::query()->create(['name' => 'one']);
        $other = Role::query()->create(['name' => 'other']);
        $keys  = [$one->id, $other->id];

        \sort($keys);

        foreach ([[$one, $other], [$other, $one]] as [$role, $excluded]) {
            $pair = ExclusionPair::of($role, $excluded);

            self::assertSame($keys, [$pair->first->id, $pair->second->id]);
            self::assertSame($keys, \array_map(static fn (Reference $reference): string => $reference->id, $pair->references()));
            self::assertSame($one->getMorphClass(), $pair->references()[1]->type);
        }
    }

    /**
     * A role paired with itself is refused, naming it, and so is a role naming
     * half a tenant, on either side.
     *
     * @return void
     */
    public function testRefusesARolePairedWithItselfOrNamingHalfATenant(): void
    {
        $role = Role::query()->create(['name' => 'clerk']);
        $half = Role::query()->create(['name' => 'half']);

        DB::table('roles')->where('id', $half->id)->update(['tenant_id' => 'a']);

        $half   = Role::query()->withoutGlobalScopes()->findOrFail($half->id);
        $itself = self::refusalOf(static fn (): ExclusionPair => ExclusionPair::of($role, Role::query()->findOrFail($role->id)));

        self::assertInstanceOf(InvalidRoleExclusionException::class, $itself);
        self::assertSame('clerk', $itself->getRole());
        self::assertInstanceOf(InvalidTenantColumnsException::class, self::refusalOf(static fn (): ExclusionPair => ExclusionPair::of($role, $half)));
        self::assertInstanceOf(InvalidTenantColumnsException::class, self::refusalOf(static fn (): ExclusionPair => ExclusionPair::of($half, $role)));
    }

    /**
     * A pair is owned by the owner of its role owned furthest down, whichever
     * role has the lower key, and two roles of tenants neither within the other
     * are refused.
     *
     * @return void
     */
    public function testIsOwnedByTheOwnerOfItsRoleOwnedFurthestDown(): void
    {
        $parent  = new Reference('stub_tenant', 'parent');
        $child   = new Reference('stub_tenant', 'child');
        $sibling = new Reference('stub_tenant', 'sibling');

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put($child, $parent)->put($sibling, $parent));

        $platform = Role::query()->create(['name' => 'platform']);
        $above    = self::ownedRole('above', $parent);
        $below    = self::ownedRole('below', $child);
        $beside   = self::ownedRole('beside', $sibling);
        $twin     = self::ownedRole('twin', $child);

        $cases = [
            [Role::query()->create(['name' => 'another']), $platform, null, null],
            [$below, $platform, $below, $child],
            [$above, $below, $below, $child],
            [$below, $twin, null, $child],
        ];

        foreach ($cases as [$role, $excluded, $owning, $owner]) {
            $pair                      = ExclusionPair::of($role, $excluded);
            [$found, $other, $claimed] = $pair->ownership();

            self::assertEquals($owner, $claimed);
            self::assertSame(($owning ?? $pair->first)->id, $found->id);
            self::assertSame($found->id === $pair->first->id ? $pair->second->id : $pair->first->id, $other->id);
        }

        $mismatch = self::refusalOf(static fn (): array => ExclusionPair::of($below, $beside)->ownership());

        self::assertInstanceOf(OwnerMismatchException::class, $mismatch);
        self::assertSame('excluded role', $mismatch->getRelatedKind());
        self::assertSame([$below->name, $beside->name], \strcmp($below->id, $beside->id) < 0
            ? [$mismatch->getRoleName(), $mismatch->getRelatedName()]
            : [$mismatch->getRelatedName(), $mismatch->getRoleName()]);
    }

    /**
     * The role the owner given owns comes first, the platform's for none,
     * whatever the tree says now; a role of the same type but another key is
     * not the owner's.
     *
     * @return void
     */
    public function testNamesTheRoleItsStoredOwnerOwnsFirst(): void
    {
        $parent = new Reference('stub_tenant', 'parent');
        $child  = new Reference('stub_tenant', 'child');

        $platform = Role::query()->create(['name' => 'platform']);
        $above    = self::ownedRole('above', $parent);
        $below    = self::ownedRole('below', $child);

        $pair  = ExclusionPair::of($above, $below);
        $names = static fn (array $roles): array => \array_map(static fn (Role $role): string => $role->name, $roles);

        self::assertSame(['below', 'above'], $names($pair->ownedBy($child)));
        self::assertSame(['above', 'below'], $names($pair->ownedBy($parent)));
        self::assertSame(['platform', 'below'], $names(ExclusionPair::of($below, $platform)->ownedBy(null)));
        self::assertSame(['below', 'platform'], $names(ExclusionPair::of($platform, $below)->ownedBy($child)));
    }

    /**
     * Return a role the tenant owns.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function ownedRole(string $name, Reference $tenant): Role
    {
        return Role::query()->withoutGlobalScopes()->create(['name' => $name, 'tenant_type' => $tenant->type, 'tenant_id' => $tenant->id]);
    }
}
