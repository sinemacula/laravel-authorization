<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exclusions;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * One way a holder holds a role of a pair of mutually exclusive roles
 * (AUTHZ-11.8, N135): a live grant of the role, or of a role below it, which
 * inherits it through its parents while the role hierarchy is enabled.
 *
 * It names the grantee of the grant, the holder itself or the identity it holds
 * the role through, the role of the pair it reaches, the path from the role
 * granted up to that role (the role alone for a direct grant), the scope the
 * grant holds in, where a check sees the role held through it, and when it
 * expires. References and scopes only, never a model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExclusionRoute
{
    /**
     * Create a new route to a role of a pair.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $role
     * @param  non-empty-list<\SineMacula\Laravel\Authorization\Support\Reference>  $path
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  \Carbon\CarbonImmutable|null  $expiresAt
     */
    public function __construct(

        /** Whom the grant is stored for: the holder, or the identity the holder holds it through. */
        public Reference $grantee,

        /** The role of the pair the route reaches. */
        public Reference $role,

        /** The roles from the one granted up to the role of the pair, in order; the role alone for a direct grant. */
        public array $path,

        /** Where the grant holds: its tenant, or the platform, whether it reaches below, and its application. */
        public GrantScope $scope,

        /** Where a check sees the role held through the grant: its scope, narrowed to the subtree of the lowest owner of a role of the path it does not lie within. */
        public GrantScope $reach,

        /** When the grant expires, in UTC; null for never. */
        public ?CarbonImmutable $expiresAt = null,
    ) {}

    /**
     * Return the role granted, the first of the path.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    public function granted(): Reference
    {
        return $this->path[0];
    }

    /**
     * Determine whether the role of the pair is granted directly, rather than
     * inherited from a role below it.
     *
     * @return bool
     */
    public function isDirect(): bool
    {
        return \count($this->path) === 1;
    }

    /**
     * Return the values the route is ordered by: its grantee, its path, then
     * its scope, each nullable value tagged.
     *
     * @return list<bool|string|null>
     */
    public function orderKey(): array
    {
        $tenant = $this->scope->tenant;

        return [
            $this->grantee->type,
            $this->grantee->id,
            ...\array_map(static fn (Reference $role): string => $role->id, $this->path),
            $tenant?->type,
            $tenant?->id,
            $this->scope->application,
            $this->scope->includeSubtree,
        ];
    }
}
