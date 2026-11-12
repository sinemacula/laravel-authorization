<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use SineMacula\Laravel\Authorization\Exceptions\InvalidRoleExclusionException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\RecordOwner;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Two roles named as a pair of mutually exclusive roles (AUTHZ-11.8, N135), in
 * the pair's canonical order, the role with the lower key first, so the pair
 * (A, B) is the pair (B, A).
 *
 * A role is never paired with itself (`InvalidRoleExclusionException`), and a
 * role naming half a tenant, which belongs to no one, is never paired
 * (`InvalidTenantColumnsException`).
 *
 * A pair is a definition, owned as the package's other definitions are (D20): a
 * definition takes only the platform's roles and those of its own tenant and
 * its tenant's ancestors, as a role takes its parent and its permissions (see
 * `RoleParity`). So a pair is owned by the owner of its role owned furthest
 * down: the platform when both roles are the platform's, else the tenant that
 * owns one of them when the other is the platform's, that tenant's own, or an
 * ancestor's. Two roles owned by tenants neither of which lies within the
 * other, such as siblings, are refused, with `OwnerMismatchException`, since no
 * definition may name both (see `ownership()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExclusionPair
{
    /**
     * Create a new pair.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $first
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $second
     */
    private function __construct(

        /** The role with the lower key. */
        public Role $first,

        /** The role with the higher key. */
        public Role $second,
    ) {}

    /**
     * Return the pair of the two roles, in the pair's order, refusing a role
     * paired with itself and one naming half a tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $excluded
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidRoleExclusionException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     */
    public static function of(Role $role, Role $excluded): self
    {
        if ($role->id === $excluded->id) {
            throw new InvalidRoleExclusionException($role->name);
        }

        RecordOwner::assertWhole($role, 'role', 'exclude');
        RecordOwner::assertWhole($excluded, 'role', 'exclude');

        return \strcmp($role->id, $excluded->id) < 0 ? new self($role, $excluded) : new self($excluded, $role);
    }

    /**
     * Return the references to the pair's two roles, in its order.
     *
     * @return array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference}
     */
    public function references(): array
    {
        return [Reference::of($this->first), Reference::of($this->second)];
    }

    /**
     * Return the role whose owner owns the pair, the other role, and that
     * owner, null for the platform, refusing two roles owned by tenants neither
     * of which lies within the other.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @return array{0: \SineMacula\Laravel\Authorization\Models\Role, 1: \SineMacula\Laravel\Authorization\Models\Role, 2: \SineMacula\Laravel\Authorization\Support\Reference|null}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    public function ownership(): array
    {
        $first  = Reference::tenantOf($this->first);
        $second = Reference::tenantOf($this->second);

        if ($second === null || TenantChain::isWithin($first, $second)) {
            return [$this->first, $this->second, $first];
        }

        if ($first === null || TenantChain::isWithin($second, $first)) {
            return [$this->second, $this->first, $second];
        }

        throw new OwnerMismatchException($this->first->name, $first, 'excluded role', $this->second->name, $second);
    }

    /**
     * Return the role the owner given owns, the platform for none, then the
     * other role: the pair's roles as its stored owner names them, however the
     * tree has moved since.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $owner
     * @return array{0: \SineMacula\Laravel\Authorization\Models\Role, 1: \SineMacula\Laravel\Authorization\Models\Role}
     */
    public function ownedBy(?Reference $owner): array
    {
        $first = Reference::tenantOf($this->first);

        return $first?->type === $owner?->type && $first?->id === $owner?->id ? [$this->first, $this->second] : [$this->second, $this->first];
    }
}
