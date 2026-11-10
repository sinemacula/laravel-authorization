<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Preview\PreviewResource;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleGraph;

/**
 * Reads the tenants a decision's sources may sit at, the anchors the scope's
 * classes of rows are cut at: rows whose tenant chains meet the anchors alike
 * read the same sources, since every source is matched to a chain by the tenant
 * it sits at (`TenantChain::grants()`, `owners()`).
 *
 * The candidates are read on the authorization connection, with no filter on
 * tenant, expiry or application, so they are never fewer than the tenants the
 * sources a check reads sit at:
 *
 * - the tenants of the grants, policies and boundaries of the subject and its
 *   identity;
 * - the tenants of the policies attached to the roles they hold anywhere, and
 *   to every role above those;
 * - the tenants owning those roles, and the permissions granted to the subject
 *   and its identity directly or through those roles;
 * - the tenants of every guardrail, and of every policy attached to the type or
 *   its records.
 *
 * The last are also the tenants whose own sources a row admitted from outside
 * the request's scope reads (its tenant chain's guardrails, and the denies
 * attached in its tenant chain), so they are told apart.
 *
 * For the target of a running use of a preview, whose every class of rows is
 * also admitted, as the previewer, where it is decided (see
 * `Preview\PreviewAdmission`), the grants are read for the previewer too, with
 * the tenants of every policy attached to preview resources, so the previewer
 * reads the same sources across each class as the target does, and a class is
 * cut wherever either's might differ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScopeAnchors
{
    /**
     * Return the tenants every source of a decision may sit at, the subject's
     * grants, and a preview's previewer's, read only when asked, and those
     * whose own sources a row admitted from outside the scope reads; each
     * tenant once.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $type
     * @param  bool  $isGrantRead
     * @return array{list<\SineMacula\Laravel\Authorization\Support\Reference>, list<\SineMacula\Laravel\Authorization\Support\Reference>}
     */
    public static function read(Subject $subject, string $type, bool $isGrantRead): array
    {
        $admitted = self::distinct([
            self::tenantsOf('guardrails', static fn (): null => null),
            self::tenantsOf('resource_policies', static fn (Builder $query, string $table): Builder => $query->where("{$table}.resource_type", $type)),
        ]);

        $previewer = Previewing::previewerOf($subject);
        $previews  = static fn (Builder $query, string $table): Builder => $query->where("{$table}.resource_type", PreviewResource::TYPE);
        $preview   = $previewer === null ? [] : [...self::grantTenantsOf($previewer), self::tenantsOf('resource_policies', $previews)];

        return [$isGrantRead ? self::distinct([...self::grantTenantsOf($subject), ...$preview, $admitted]) : $admitted, $admitted];
    }

    /**
     * Return the tenants of the grants, policies and boundaries of the subject
     * and its identity, of the policies attached to the roles they hold and
     * every role above them, and of the owners of those roles and of the
     * permissions granted.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<list<\SineMacula\Laravel\Authorization\Support\Reference>>
     */
    private static function grantTenantsOf(Subject $subject): array
    {
        $grantees = self::granteesOf($subject);
        $isHeld   = static fn (Builder $query, string $table): Builder => self::whereGrantee($query, $table, $grantees);
        $roles    = \array_keys(RoleGraph::reach(self::keysOf('authorizable_roles', 'role_id', $isHeld)));

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $roleClass */
        $roleClass = ModelClasses::get('role');
        $roleType  = (new $roleClass)->getMorphClass();

        $direct      = self::keysOf('authorizable_permissions', 'permission_id', $isHeld);
        $inherited   = self::keysOf('role_permissions', 'permission_id', static fn (Builder $query, string $table): Builder => $query->whereIn("{$table}.role_id", $roles));
        $permissions = [...$direct, ...$inherited];
        $grants      = ['authorizable_roles', 'authorizable_permissions', 'authorizable_policies', 'authorizable_boundaries'];
        $byRoles     = static fn (Builder $query, string $table): Builder => $query->where("{$table}.authorizable_type", $roleType)->whereIn("{$table}.authorizable_id", $roles);

        return [
            ...\array_map(static fn (string $table): array => self::tenantsOf($table, $isHeld), $grants),
            self::tenantsOf('authorizable_policies', $byRoles),
            self::tenantsOf('roles', static fn (Builder $query, string $table): Builder => $query->whereIn("{$table}.id", $roles)),
            self::tenantsOf('permissions', static fn (Builder $query, string $table): Builder => $query->whereIn("{$table}.id", $permissions)),
        ];
    }

    /**
     * Return the subject and its identity, when that is another model, as the
     * grant tables name them; one that is not a model holds no grant there.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private static function granteesOf(Subject $subject): array
    {
        $grantees = [];

        foreach ([$subject->subject, $subject->identity] as $grantee) {
            if (!$grantee instanceof Model) {
                continue;
            }

            $grantees[] = Reference::of($grantee);
        }

        return $grantees;
    }

    /**
     * Limit a grant query to the rows granted to one of the grantees; to none
     * when there are none.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @return \Illuminate\Database\Query\Builder
     */
    private static function whereGrantee(Builder $query, string $table, array $grantees): Builder
    {
        return $query->where(static function (Builder $query) use ($table, $grantees): void {
            $query->whereRaw(QueryAuthorizer::NO_ROW);

            foreach ($grantees as $grantee) {
                $query->orWhere(static fn (Builder $query): Builder => $query->where("{$table}.authorizable_type", $grantee->type)
                    ->where("{$table}.authorizable_id", $grantee->id));
            }
        });
    }

    /**
     * Return the distinct values of a column of the table's rows the constraint
     * keeps.
     *
     * @param  string  $name
     * @param  string  $column
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): mixed  $constrain
     * @return list<string>
     */
    private static function keysOf(string $name, string $column, \Closure $constrain): array
    {
        $table = self::table($name);
        $query = AuthorizationConnection::connection()->table($table)->useWritePdo();

        $constrain($query, $table);

        /** @var list<mixed> $keys */
        $keys = $query->distinct()->pluck("{$table}.{$column}")->all();

        return \array_map(static fn (mixed $key): string => \is_scalar($key) ? (string) $key : '', $keys);
    }

    /**
     * Return the distinct tenants of the table's rows the constraint keeps.
     *
     * @param  string  $name
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): mixed  $constrain
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private static function tenantsOf(string $name, \Closure $constrain): array
    {
        $table = self::table($name);
        $query = AuthorizationConnection::connection()->table($table)->useWritePdo()->whereNotNull("{$table}.tenant_type")->whereNotNull("{$table}.tenant_id");

        $constrain($query, $table);

        $tenants = [];

        foreach ($query->distinct()->get(["{$table}.tenant_type", "{$table}.tenant_id"]) as $row) {
            ['tenant_type' => $type, 'tenant_id' => $id] = (array) $row;

            $tenants[] = new Reference(\is_scalar($type) ? (string) $type : '', \is_scalar($id) ? (string) $id : '');
        }

        return $tenants;
    }

    /**
     * Return the tenants, each once, in the order first found.
     *
     * @param  list<list<\SineMacula\Laravel\Authorization\Support\Reference>>  $lists
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private static function distinct(array $lists): array
    {
        $tenants = [];

        foreach (\array_merge(...$lists) as $tenant) {
            $tenants[\serialize($tenant)] = $tenant;
        }

        return \array_values($tenants);
    }

    /**
     * Return the table `authorization.tables` names for the key.
     *
     * @param  string  $name
     * @return string
     */
    private static function table(string $name): string
    {
        return TableNames::get($name);
    }
}
