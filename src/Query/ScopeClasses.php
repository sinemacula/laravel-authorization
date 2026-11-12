<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use SineMacula\Laravel\Authorization\Config\ConfigValue;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\Dialects\Dialects;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Splits a model's rows into the classes `check()` decides alike, as
 * `ResourceScope` decides each row:
 *
 * - every row of a tenantless model, or a row of no tenant, in the request's
 *   scope (A);
 * - with a tenant active, a row within its subtree, in its own tenant's scope
 *   (B): the rows of each anchor within the subtree, the active tenant
 *   included, in that tenant (B(D,=)); and, unless the tree is flat, the rows
 *   strictly below an anchor with no anchor between, standing below it
 *   (B(D,<));
 * - when the subject holds the action platform-wide, as `ResourceScope` asks it
 *   once at platform scope, every other row of a tenant, at platform scope,
 *   with its own chain's guardrails and attached denies (C): those of each
 *   anchor outside the subtree (C(X,=)), below it (C(X,<)), and of no anchor
 *   (C(none)). Otherwise `check()` denies those rows as `tenant_scope`.
 *
 * The anchors are the tenants the decision's sources sit at (`ScopeAnchors`),
 * and the forest they form is read through the bound tree: which anchors are
 * within the active tenant's subtree by `isWithin()`, and which lie below which
 * by each anchor's chain of ancestors, read once. Rows strictly below an anchor
 * with no anchor between read exactly the sources the anchor's scope standing
 * below it reads, since no source sits between them.
 *
 * The classes compare tenants as PHP does, while `check()` matches sources to
 * tenants in SQL; so whenever a class is cut below an anchor or admitted from
 * outside, the tenant columns of the authorization tables must compare bytes
 * (`column_collation`). More anchors than
 * `authorization.query_scoping.max_anchors`, or more classes than `max_scopes`,
 * are refused (`too_many_scopes`), each counted before a class is cut, so the
 * work of cutting is bounded by the limits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScopeClasses
{
    /** @var list<string> The authorization tables whose tenant columns a check matches sources by. */
    private const array TENANT_TABLES = [
        'roles', 'permissions', 'policies', 'authorizable_roles', 'break_glass', 'authorizable_permissions', 'authorizable_policies', 'resource_policies',
        'authorizable_boundaries', 'guardrails',
    ];

    /** @var int The most anchors when `authorization.query_scoping.max_anchors` is not set. */
    private const int MAX_ANCHORS = 64;

    /** @var int The most classes when `authorization.query_scoping.max_scopes` is not set. */
    private const int MAX_SCOPES = 16;

    /**
     * Return the classes of the model's rows, refusing those it cannot cut
     * exactly.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Query\SchemaInspector  $inspector
     * @return list<\SineMacula\Laravel\Authorization\Query\ScopeClass>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    public static function of(ResourceShape $shape, Subject $subject, string $action, SchemaInspector $inspector): array
    {
        if ($shape->idColumn === null) {
            return [new ScopeClass(QueryAuthorizer::EVERY_ROW)];
        }

        $membership = new TenantMembership($shape, $action);
        $active     = TenantScope::currentChain()->tenant();
        $isAdmitted = TenantScope::within(null, TenantScope::currentApplication(), static fn (): bool => SubjectGrants::holdsPermission($subject, $action));
        $isFlat     = TenantChain::tree() instanceof FlatTenantTree;
        $none       = new ScopeClass($membership->ofNone());

        if ($active === null && !$isAdmitted) {
            return [$none];
        }

        if (!$isFlat || $isAdmitted) {
            self::assertExactTables($shape, $action, $inspector);
        }

        [$inScope, $outside] = self::anchorsOf($shape, $subject, $action, $active, $isAdmitted);

        // Each anchor makes one class, two unless the tree is flat, and rows
        // admitted from outside one more on no anchor's chain.
        $each  = $isFlat ? 1 : 2;
        $count = 1 + \count($inScope) * $each + ($isAdmitted ? \count($outside) * $each + 1 : 0);

        if ($count > self::limit('max_scopes', self::MAX_SCOPES)) {
            self::refuse($shape, $action, 'max_scopes');
        }

        $classes = [$none, ...self::branch($membership, $inScope, $isFlat, false, [])];

        return $isAdmitted ? [...$classes, ...self::admitted($membership, $outside, $isFlat, $active)] : $classes;
    }

    /**
     * Return the anchors within the active tenant's subtree, the active tenant
     * first, and those outside it a row admitted from outside reads the own
     * sources of, refusing more anchors than allowed. Under the flat tree only
     * the active tenant is within its own subtree.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $active
     * @param  bool  $isAdmitted
     * @return array{list<\SineMacula\Laravel\Authorization\Support\Reference>, array<int, \SineMacula\Laravel\Authorization\Support\Reference>}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private static function anchorsOf(ResourceShape $shape, Subject $subject, string $action, ?Reference $active, bool $isAdmitted): array
    {
        $isGrantRead           = !(TenantChain::tree() instanceof FlatTenantTree) && $active !== null;
        [$sources, $admitting] = $isGrantRead || $isAdmitted ? ScopeAnchors::read($subject, $shape->type, $isGrantRead) : [[], []];

        $others = \array_filter($sources, static fn (Reference $tenant): bool => $active === null || !self::isSame($tenant, $active));

        if (\count($others) + ($active === null ? 0 : 1) > self::limit('max_anchors', self::MAX_ANCHORS)) {
            self::refuse($shape, $action, 'max_anchors');
        }

        $inScope = $active === null ? [] : [$active, ...\array_filter($others, static fn (Reference $tenant): bool => TenantChain::isWithin($tenant, $active))];
        $outside = \array_filter($admitting, static fn (Reference $tenant): bool => $active === null || !TenantChain::isWithin($tenant, $active));

        return [$inScope, $outside];
    }

    /**
     * Return the classes of one branch: the rows of each anchor, and, unless
     * the tree is flat, those strictly below it with no anchor between, each
     * meeting the further conditions given too.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\TenantMembership  $membership
     * @param  array<int, \SineMacula\Laravel\Authorization\Support\Reference>  $anchors
     * @param  bool  $isFlat
     * @param  bool  $isAdmitted
     * @param  list<string>  $outside
     * @return list<\SineMacula\Laravel\Authorization\Query\ScopeClass>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private static function branch(TenantMembership $membership, array $anchors, bool $isFlat, bool $isAdmitted, array $outside): array
    {
        $chains  = $isFlat ? [] : self::chainsOf($anchors);
        $classes = [];

        foreach ($anchors as $anchor) {
            $classes[] = new ScopeClass(Conditions::all([$membership->equalTo($anchor), ...$outside]), $anchor, false, $isAdmitted);

            if ($isFlat) {
                continue;
            }

            $lower = \array_filter($anchors, static fn (Reference $other): bool => !self::isSame($other, $anchor) && self::isOnChain($anchor, $chains[self::keyOf($other)] ?? []));
            $apart = \array_map(static fn (Reference $other): string => Conditions::not($membership->within($other)), $lower);

            $below     = Conditions::all([$membership->present(), $membership->within($anchor), Conditions::not($membership->equalTo($anchor)), ...$apart, ...$outside]);
            $classes[] = new ScopeClass($below, $anchor, true, $isAdmitted);
        }

        return $classes;
    }

    /**
     * Return each anchor's chain, the anchor and then its ancestors, read once
     * through the bound tree, keyed by the anchor: an anchor lies within
     * another exactly when the other is on its chain.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Support\Reference>  $anchors
     * @return array<string, list<\SineMacula\Laravel\Authorization\Support\Reference>>
     */
    private static function chainsOf(array $anchors): array
    {
        $tree   = TenantChain::tree();
        $chains = [];

        foreach ($anchors as $anchor) {
            $chains[self::keyOf($anchor)] = [$anchor, ...$tree->ancestors($anchor)];
        }

        return $chains;
    }

    /**
     * Determine whether the tenant is on the chain, byte for byte.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $chain
     * @return bool
     */
    private static function isOnChain(Reference $tenant, array $chain): bool
    {
        return \array_filter($chain, static fn (Reference $link): bool => self::isSame($link, $tenant)) !== [];
    }

    /**
     * Return the classes of the rows a platform-wide grant admits from outside
     * the active tenant's subtree, every tenant's when none is active: those of
     * each anchor outside it, and those on no anchor's chain.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\TenantMembership  $membership
     * @param  array<int, \SineMacula\Laravel\Authorization\Support\Reference>  $anchors
     * @param  bool  $isFlat
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $active
     * @return list<\SineMacula\Laravel\Authorization\Query\ScopeClass>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private static function admitted(TenantMembership $membership, array $anchors, bool $isFlat, ?Reference $active): array
    {
        $outside = $active === null ? [] : [Conditions::not($membership->within($active))];
        $apart   = \array_map(static fn (Reference $anchor): string => Conditions::not($membership->within($anchor)), $anchors);

        $none = new ScopeClass(Conditions::all([$membership->present(), ...$outside, ...$apart]), null, false, true);

        return [...self::branch($membership, $anchors, $isFlat, true, $outside), $none];
    }

    /**
     * Refuse the query unless the tenant columns of every authorization table
     * compare bytes, as PHP compares tenants.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Query\SchemaInspector  $inspector
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private static function assertExactTables(ResourceShape $shape, string $action, SchemaInspector $inspector): void
    {
        $connection = AuthorizationConnection::connection();
        $dialect    = Dialects::for($connection->getDriverName());

        foreach (self::TENANT_TABLES as $name) {
            $table = TableNames::get($name);

            foreach (['tenant_type', 'tenant_id'] as $column) {
                if ($dialect === null || !$inspector->isExactCollation($connection, $dialect, $table, $column)) {
                    throw QueryScopeRefusedException::of($action, $shape->type, new Refusal(RefusalReason::COLUMN_COLLATION, null, null, "{$table}.{$column}"));
                }
            }
        }
    }

    /**
     * Return a limit of `authorization.query_scoping`, or its default when it
     * is left out, refusing one that is not a whole number of at least one.
     *
     * @param  string  $key
     * @param  int  $default
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function limit(string $key, int $default): int
    {
        return ConfigValue::integer("query_scoping.{$key}", $default, 1);
    }

    /**
     * Refuse the query for having more anchors or classes than the limit
     * allows.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  string  $action
     * @param  string  $limit
     * @return never
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private static function refuse(ResourceShape $shape, string $action, string $limit): never
    {
        throw QueryScopeRefusedException::of($action, $shape->type, new Refusal(RefusalReason::TOO_MANY_SCOPES, null, null, "authorization.query_scoping.{$limit}"));
    }

    /**
     * Return the tenant as a key, its type and id apart.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     */
    private static function keyOf(Reference $tenant): string
    {
        return $tenant->type . "\0" . $tenant->id;
    }

    /**
     * Determine whether two tenants are the same, byte for byte.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $other
     * @return bool
     */
    private static function isSame(Reference $tenant, Reference $other): bool
    {
        return $tenant->type === $other->type && $tenant->id === $other->id;
    }
}
