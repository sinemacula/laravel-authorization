<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exclusions\Support;

use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A write weighed against the pairs of mutually exclusive roles (AUTHZ-11.8,
 * N136): the role grants it wrote or would write, or the parent it would give a
 * role, so the conflict report reads the holdings as they are after it and
 * keeps only the conflicts it creates, those a route of its own takes part in.
 *
 * A grant already written is read as stored; a break-glass activation proposed
 * is read beside the stored grants and activations; a parent proposed replaces
 * the role's stored one. A route is the write's when its grant is one the write
 * makes, by grantee, role, tenant and application, or when its path steps from
 * the role re-parented to the parent proposed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExclusionWrite
{
    /**
     * Create the write.
     *
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: string, 2: \SineMacula\Laravel\Authorization\Support\GrantScope}>  $grants
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>  $proposed
     * @param  array<string, string>  $parents
     */
    private function __construct(

        /** The grants the write makes, each its grantee, the key of its role and its scope. */
        private array $grants = [],

        /** The break-glass activations the write would store, read beside the stored ones. */
        public array $proposed = [],

        /** The parent the write would give a role, each by the role's key. */
        public array $parents = [],
    ) {}

    /**
     * Return the write of the grants of the roles, by key with the scope each
     * was written in, already stored for the grantee.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  list<array{0: string, 1: \SineMacula\Laravel\Authorization\Support\GrantScope}>  $grants
     * @return self
     */
    public static function granted(Reference $grantee, array $grants): self
    {
        return new self(\array_map(static fn (array $grant): array => [$grantee, $grant[0], $grant[1]], $grants));
    }

    /**
     * Return the write of a break-glass activation of the role for the grantee
     * in the scope, not stored, read as a live one beside the stored ones.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  string  $role
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return self
     */
    public static function proposed(Reference $grantee, string $role, GrantScope $scope): self
    {
        $row = new GrantRow(GrantTarget::ROLE->value, $role, $grantee, $scope, ['expires_at' => null, 'created_at' => null, 'updated_at' => null], null);

        return new self([[$grantee, $role, $scope]], [$row]);
    }

    /**
     * Return the write of the parent given to the role, both by key.
     *
     * @param  string  $role
     * @param  string  $parent
     * @return self
     */
    public static function reparented(string $role, string $parent): self
    {
        return new self(parents: [$role => $parent]);
    }

    /**
     * Determine whether the write creates the conflict: either of its routes is
     * the write's.
     *
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict  $conflict
     * @return bool
     */
    public function makes(ExclusionConflict $conflict): bool
    {
        return $this->isMade($conflict->first) || $this->isMade($conflict->second);
    }

    /**
     * Determine whether the route is the write's: its grant is one the write
     * makes, or its path steps from a role to the parent the write gives it.
     *
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute  $route
     * @return bool
     */
    private function isMade(ExclusionRoute $route): bool
    {
        foreach ($this->grants as [$grantee, $role, $scope]) {
            if (self::isSameGrant($route, $grantee, $role, $scope)) {
                return true;
            }
        }

        $path = $route->path;

        for ($step = 1; $step < \count($path); $step++) {
            if (($this->parents[$path[$step - 1]->id] ?? null) === $path[$step]->id) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the route's grant is the grantee's grant of the role in
     * the scope's tenant and application, the one row a grantee holds there.
     *
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute  $route
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  string  $role
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return bool
     */
    private static function isSameGrant(ExclusionRoute $route, Reference $grantee, string $role, GrantScope $scope): bool
    {
        $held    = $route->scope;
        $written = [ExclusionHoldings::key($grantee), $role, $scope->tenant?->type, $scope->tenant?->id, $scope->application];

        return [ExclusionHoldings::key($route->grantee), $route->granted()->id, $held->tenant?->type, $held->tenant?->id, $held->application] === $written;
    }
}
