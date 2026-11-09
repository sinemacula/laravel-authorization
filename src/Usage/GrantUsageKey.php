<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewOrder;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The key grant usage is recorded under (N102): a stable digest of one grant
 * route, its source kind, its target, its grantee, its tenant and application
 * as stored, and its reach, the roles it runs through from the role granted up
 * to the one carrying the target.
 *
 * A check and an access review build it from the same parts, so a route a check
 * observed and the review row of that route share it. The reach a grant's
 * `include_subtree` sets is no part of it, and neither is its expiry, so a
 * grant whose expiry or reach is rewritten keeps its use; a grant revoked and
 * made again keeps its key too, and is told apart by its creation (see
 * `StoredGrant`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GrantUsageKey
{
    /**
     * Return the key of the route of the kind by which the grantee's grant,
     * stored in the scope, reaches the target through the roles of the path.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array{string|null, string|null, string|null}  $scope
     * @param  list<string>  $path
     * @return string
     */
    public static function of(SourceKind $kind, Reference $target, Reference $grantee, array $scope, array $path): string
    {
        return \hash('sha256', ReviewOrder::key([$kind->value, $target->type, $target->id, $grantee->type, $grantee->id, ...$scope, ...$path]));
    }

    /**
     * Return the key of the route an access review row lists.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @return string
     */
    public static function ofRow(ReviewRow $row): string
    {
        $origin = $row->originScope;
        $path   = \array_map(static fn (Reference $role): string => $role->id, $row->rolePath);

        return self::of($row->sourceKind, $row->target, $row->grantee, [$origin?->tenantType, $origin?->tenantId, $origin?->application], $path);
    }

    /**
     * Return the key of the route of the kind that starts from the stored row
     * and reaches the target through the roles of the chain, as an access
     * review lists it.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $kind
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow  $start
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $target
     * @param  list<string>  $chain
     * @return string
     */
    public static function ofStored(SourceKind $kind, GrantRow $start, Reference $target, array $chain): string
    {
        $origin = $start->originScope();

        return self::of($kind, $target, $start->grantee, [$origin?->tenantType, $origin?->tenantId, $origin?->application], $chain);
    }
}
