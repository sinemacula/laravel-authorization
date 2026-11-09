<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What roles carry, as an access review reads it: the live permission edges of
 * roles, and the live policy attachments to roles, each read in one query on
 * the write connection, and the routes by which a role's grant reaches them,
 * through the role itself or a role above it.
 *
 * A permission edge holds wherever the role does; in a review of what applies
 * in a tenant, only a permission the tenant sees counts. A policy attachment to
 * a role holds in its own scope, and reaches the role's holder only where the
 * role's grant holds too (see `ReviewRun::intersects()`): in a review of what
 * applies in a tenant, the attachment must apply there as well; in any other,
 * it must hold in the application the review selects. An attachment of an
 * inline policy to a role it does not belong to is never read, as a check never
 * applies it (see `InlinePolicies`).
 *
 * The routes of one grant are collected in the review's order: by the roles of
 * the chain to the carrying role, then by the row each rests on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RoleCarriers
{
    /**
     * Return the live permission edges of the roles with the keys, or of every
     * role carrying the permission given, each list by its role's key.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  list<string>|null  $roles
     * @param  string|null  $permission
     * @return array<string, list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>>
     */
    public static function edges(ReviewRun $run, ?array $roles, ?string $permission = null): array
    {
        if ($roles === []) {
            return [];
        }

        $table = Definitions::edges();
        $query = $run->visible($run->live(GrantRows::edges(), $table), GrantTarget::PERMISSION, $table . '.permission_id');

        if ($roles !== null) {
            $query->whereIn($table . '.role_id', $roles);
        }

        if ($permission !== null) {
            $query->where($table . '.permission_id', $permission);
        }

        return self::byGrantee($query->get(), GrantRow::EDGE, Definitions::morph(GrantTarget::ROLE));
    }

    /**
     * Return the live policy attachments to the roles with the keys, or to
     * every role the policy given is attached to, that the review reads, each
     * list by its role's key.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  list<string>|null  $roles
     * @param  string|null  $policy
     * @return array<string, list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>>
     */
    public static function attachments(ReviewRun $run, ?array $roles, ?string $policy = null): array
    {
        if ($roles === []) {
            return [];
        }

        $table = GrantTarget::POLICY->table();
        $query = InlinePolicies::attachedToTheirGrantee($run->live(GrantRows::of(GrantTarget::POLICY), $table), $table)
            ->where($table . '.authorizable_type', Definitions::morph(GrantTarget::ROLE));

        $run->isApplicability() ? $run->constrain($query, $table) : $run->scope->application->constrain($query, $table);

        if ($roles !== null) {
            $query->whereIn($table . '.authorizable_id', $roles);
        }

        if ($policy !== null) {
            $query->where($table . '.policy_id', $policy);
        }

        return self::byGrantee($query->get(), GrantTarget::POLICY->value);
    }

    /**
     * Collect the routes by which the role grant reaches the permissions the
     * roles of its chain carry: one for each role of the chain and each edge of
     * it, through the chain up to that role.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow  $grant
     * @param  list<string>  $chain
     * @param  array<string, list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>>  $edges
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $via
     * @return void
     */
    public static function throughEdges(RowCollector $rows, Reference $subject, GrantRow $grant, array $chain, array $edges, ?Reference $via = null): void
    {
        $type = Definitions::morph(GrantTarget::PERMISSION);

        self::collect($rows, $subject, $grant, $chain, $edges, $via, static fn (GrantRow $edge): array => [SourceKind::ROLE_PERMISSION, new Reference($type, $edge->targetId)]);
    }

    /**
     * Collect the routes by which the role grant reaches the policies attached
     * to the roles of its chain: one for each role of the chain and each
     * attachment of it that holds where the grant does, through the chain up to
     * that role.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow  $grant
     * @param  list<string>  $chain
     * @param  array<string, list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>>  $attachments
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $via
     * @return void
     */
    public static function throughAttachments(
        ReviewRun $run,
        RowCollector $rows,
        Reference $subject,
        GrantRow $grant,
        array $chain,
        array $attachments,
        ?Reference $via = null,
    ): void {
        $type  = Definitions::morph(GrantTarget::POLICY);
        $scope = $grant->scope;
        $held  = [];

        foreach ($attachments as $role => $rowsOfRole) {
            $holds = static fn (GrantRow $attachment): bool => $scope !== null && $attachment->scope !== null && $run->intersects($scope, $attachment->scope);

            $held[$role] = \array_values(\array_filter($rowsOfRole, $holds));
        }

        $target = static fn (GrantRow $attachment): array => [SourceKind::ROLE_POLICY, new Reference($type, $attachment->targetId)];

        self::collect($rows, $subject, $grant, $chain, $held, $via, $target);
    }

    /**
     * Collect a route for each role of the chain and each row it carries,
     * through the chain up to that role, in the order of their routes.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow  $grant
     * @param  list<string>  $chain
     * @param  array<string, list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>>  $carried
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $via
     * @param  \Closure(\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow): array{\SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind, \SineMacula\Laravel\Authorization\Support\Reference}  $target
     * @return void
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    private static function collect(RowCollector $rows, Reference $subject, GrantRow $grant, array $chain, array $carried, ?Reference $via, \Closure $target): void
    {
        $routes = [];

        foreach ($chain as $depth => $role) {
            $path = \array_slice($chain, 0, $depth + 1);

            foreach ($carried[$role] ?? [] as $row) {
                $routes[] = ['key' => [...$path, $row->key()], 'path' => $path, 'row' => $row];
            }
        }

        \usort($routes, static fn (array $one, array $other): int => ReviewOrder::compare($one['key'], $other['key']));

        foreach ($routes as $route) {
            [$kind, $reference] = $target($route['row']);

            $rows->route($kind, $subject, $grant, $reference, $route['path'], [$route['row']], $via);
        }
    }

    /**
     * Return the stored rows the query read, of the source, each list by its
     * grantee's key, the grantee of an edge being a role of the type given.
     *
     * @param  iterable<object>  $read
     * @param  string  $source
     * @param  string|null  $roleType
     * @return array<string, list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>>
     */
    private static function byGrantee(iterable $read, string $source, ?string $roleType = null): array
    {
        $rows = [];

        foreach ($read as $row) {
            $stored = GrantRow::from($row, $source, $roleType);

            $rows[$stored->grantee->id][] = $stored;
        }

        return $rows;
    }
}
