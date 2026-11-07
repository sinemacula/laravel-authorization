<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleGraph;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Whether anything that caps or denies a subject could limit a permission
 * anywhere a delegated grant of it would reach, for the possession route of the
 * grant (N77). The route proves the grant contained only when nothing could:
 * when in doubt, the permission is limited.
 *
 * What is read:
 *
 * - every source the check of the permission reads in the grant's scope: the
 *   policies, the boundaries, the guardrails and the session caps, a custom
 *   policy resolver's included;
 * - as stored, on the write connection, outside every tenant scope, whatever
 *   their application and expiry: the policies attached to the subject's
 *   principal and identity, and to every role either holds and the roles above
 *   them, the policies attached to any resource, the boundaries of the
 *   principal and the identity, and the guardrails; each held, attached or set
 *   in a tenant of the grant's reach: the platform, the grant's tenant and its
 *   ancestors, and, for a grant reaching below its tenant, every tenant below
 *   it; for a platform-wide grant, every tenant.
 *
 * The permission is limited when any deny statement among them names an action
 * the permission covers, with conditions, resource patterns or none; when a
 * boundary or a guardrail has no allow statement naming every action the
 * permission covers, with no condition and on every resource; when a session
 * cap does not cover every action it covers; and when a document cannot be
 * read. Patterns are compared as `fnmatch()` compares names, the only wildcard
 * being `*`: a deny of `posts:edit` limits a grant of `posts:*`, and a cap of
 * `posts:*` covers a grant of `posts:edit`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PossessionLimits
{
    /**
     * Determine whether anything that applies to the subject anywhere in the
     * operation's reach could limit the permission.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $permission
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckSources  $sources
     * @return bool
     */
    public static function isLimited(Subject $subject, string $permission, OperationResource $operation, CheckSources $sources): bool
    {
        try {
            [$denying, $capping] = self::stored($subject, $operation);
        } catch (InvalidPolicyDocumentException) {
            return true;
        }

        $capping = [...$capping, ...$sources->boundaries, ...$sources->guardrails ?? []];

        return self::denies([...$sources->policies, ...$denying, ...$capping], $permission)
            || !self::isCoveredByEvery($capping, $permission)
            || !self::isCoveredByCaps($sources->session, $permission);
    }

    /**
     * Determine whether two action patterns name an action in common. A pattern
     * without `*` names itself alone; two with one each overlap when the text
     * before the first `*` of one starts the other's, and the text after the
     * last `*` of one ends the other's.
     *
     * @param  string  $pattern
     * @param  string  $other
     * @return bool
     */
    public static function isOverlapping(string $pattern, string $other): bool
    {
        if (!\str_contains($pattern, '*') || !\str_contains($other, '*')) {
            return \fnmatch($pattern, $other, \FNM_NOESCAPE) || \fnmatch($other, $pattern, \FNM_NOESCAPE);
        }

        [$head, $tail]           = self::ends($pattern);
        [$otherHead, $otherTail] = self::ends($other);

        return (\str_starts_with($head, $otherHead) || \str_starts_with($otherHead, $head)) && (\str_ends_with($tail, $otherTail) || \str_ends_with($otherTail, $tail));
    }

    /**
     * Return the policies stored for the subject in the operation's reach that
     * may deny (its policies, its roles' and every resource's), and those that
     * cap (its boundaries and the guardrails), hydrated.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @return array{list<\SineMacula\Laravel\Authorization\Evaluation\Policy>, list<\SineMacula\Laravel\Authorization\Evaluation\Policy>}
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function stored(Subject $subject, OperationResource $operation): array
    {
        $reach    = self::reach($operation);
        $grantees = [];

        foreach ([$subject->subject, $subject->identity] as $side) {
            if (!$side instanceof Model) {
                continue;
            }

            $grantees[] = Reference::of($side);
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $role */
        $role  = config('authorization.models.role', Role::class);
        $roles = \array_keys(RoleGraph::reach(self::keys('authorizable_roles', 'role_id', $grantees, $reach)));
        $held  = [...$grantees, ...\array_map(static fn (string $key): Reference => new Reference((new $role)->getMorphClass(), $key), $roles)];

        $denying = [...self::keys('authorizable_policies', 'policy_id', $held, $reach), ...self::keys('resource_policies', 'policy_id', null, $reach)];
        $capping = [...self::keys('authorizable_boundaries', 'policy_id', $grantees, $reach), ...self::keys('guardrails', 'policy_id', null, $reach)];

        return [self::hydrated($denying), self::hydrated($capping)];
    }

    /**
     * Return the distinct keys in the column of the rows of the table that the
     * grantees hold, or of every row for no grantees, in a tenant of the reach.
     *
     * @param  string  $table
     * @param  string  $column
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>|null  $grantees
     * @param  \Closure(\SineMacula\Laravel\Authorization\Support\Reference|null): bool  $reach
     * @return list<string>
     */
    private static function keys(string $table, string $column, ?array $grantees, \Closure $reach): array
    {
        if ($grantees === []) {
            return [];
        }

        /** @var string $name */
        $name  = config('authorization.tables.' . $table, $table);
        $query = AuthorizationConnection::connection()->table($name)->useWritePdo();

        $query->where(static function ($query) use ($grantees): void {
            foreach ($grantees ?? [] as $grantee) {
                $query->orWhere(static fn ($row) => $row->where('authorizable_type', $grantee->type)->where('authorizable_id', $grantee->id));
            }
        });

        $keys = [];

        foreach ($query->get([$column . ' as granted', 'tenant_type', 'tenant_id']) as $row) {
            /** @var array{granted: int|string, tenant_type: string|null, tenant_id: int|string|null} $columns */
            $columns = (array) $row;
            $tenant  = $columns['tenant_type'] === null ? null : new Reference($columns['tenant_type'], (string) $columns['tenant_id']);

            if (!$reach($tenant)) {
                continue;
            }

            $keys[(string) $columns['granted']] = (string) $columns['granted'];
        }

        return \array_values($keys);
    }

    /**
     * Return whether a row held in a tenant, or platform-wide, is in the
     * operation's reach: a platform-wide row always is, every row is for a
     * platform-wide grant, and otherwise a row of the grant's tenant or one of
     * its ancestors, or, for a grant reaching below its tenant, of a tenant
     * below it.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @return \Closure(\SineMacula\Laravel\Authorization\Support\Reference|null): bool
     */
    private static function reach(OperationResource $operation): \Closure
    {
        $tenant = $operation->tenant;
        $below  = $operation->change?->scope->includeSubtree ?? true;
        $chain  = \array_map(static fn (Reference $link): string => $link->type . "\0" . $link->id, TenantChain::of($tenant, TenantChain::tree())->tenants);

        return static fn (?Reference $row): bool => $row === null
            || $tenant                                   === null
            || \in_array($row->type . "\0" . $row->id, $chain, true)
            || ($below && TenantChain::isWithin($row, $tenant));
    }

    /**
     * Return the stored policies with the keys, hydrated; one that is gone, or
     * whose document cannot be read, throws.
     *
     * @param  list<string>  $keys
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function hydrated(array $keys): array
    {
        $policies = [];

        foreach ($keys as $key) {
            $policies[] = PolicyDocument::hydrate(InlinePolicies::stored($key) ?? throw new InvalidPolicyDocumentException($key, 'the policy is gone'));
        }

        return $policies;
    }

    /**
     * Determine whether a deny statement of any of the policies names an action
     * the permission covers.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  string  $permission
     * @return bool
     */
    private static function denies(array $policies, string $permission): bool
    {
        foreach ($policies as $policy) {
            foreach ($policy->statements as $statement) {
                if ($statement->effect === PolicyEffect::DENY && self::names($statement, $permission)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Determine whether the statement names any action the permission covers:
     * one of its `actions` overlaps it, or none of its `not_actions` covers it
     * whole.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  string  $permission
     * @return bool
     */
    private static function names(Statement $statement, string $permission): bool
    {
        return $statement->notActions === null ? self::hasOverlapping($statement->actions ?? [], $permission) : !self::isCoveredByAny($statement->notActions, $permission);
    }

    /**
     * Determine whether every one of the policies, each a boundary or a
     * guardrail, allows every action the permission covers, with no condition,
     * on every resource.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  string  $permission
     * @return bool
     */
    private static function isCoveredByEvery(array $policies, string $permission): bool
    {
        foreach ($policies as $policy) {
            if (!self::allowsWhole($policy, $permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine whether the policy has an allow statement naming every action
     * the permission covers, with no condition, on every resource.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @param  string  $permission
     * @return bool
     */
    private static function allowsWhole(Policy $policy, string $permission): bool
    {
        foreach ($policy->statements as $statement) {
            if (self::isUnconditionalAllow($statement) && self::namesWhole($statement, $permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the statement is an allow with no condition and no
     * principals, on every resource.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @return bool
     */
    private static function isUnconditionalAllow(Statement $statement): bool
    {
        $everywhere = $statement->notResources === null && ($statement->resources === null || \in_array('*', $statement->resources, true));
        $plain      = $statement->conditions   === []   && $statement->principals === null;

        return $statement->effect === PolicyEffect::ALLOW && $plain && $everywhere;
    }

    /**
     * Determine whether the statement names every action the permission covers:
     * one of its `actions` covers it whole, or none of its `not_actions` names
     * any of them.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  string  $permission
     * @return bool
     */
    private static function namesWhole(Statement $statement, string $permission): bool
    {
        return $statement->notActions === null
            ? self::isCoveredByAny($statement->actions ?? [], $permission)
            : !self::hasOverlapping($statement->notActions, $permission);
    }

    /**
     * Determine whether every session cap covers every action the permission
     * covers.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\SessionCaps  $session
     * @param  string  $permission
     * @return bool
     */
    private static function isCoveredByCaps(SessionCaps $session, string $permission): bool
    {
        foreach ($session->caps as [, $patterns]) {
            if (!self::isCoveredByAny($patterns, $permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine whether one of the patterns covers every action the permission
     * covers: it matches the permission's name taken literally.
     *
     * @param  list<string>  $patterns
     * @param  string  $permission
     * @return bool
     */
    private static function isCoveredByAny(array $patterns, string $permission): bool
    {
        return SessionCaps::covers($patterns, $permission);
    }

    /**
     * Determine whether one of the patterns names an action the permission
     * covers.
     *
     * @param  list<string>  $patterns
     * @param  string  $permission
     * @return bool
     */
    private static function hasOverlapping(array $patterns, string $permission): bool
    {
        foreach ($patterns as $pattern) {
            if (self::isOverlapping($pattern, $permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the text before the first `*` of a pattern and after its last.
     *
     * @param  string  $pattern
     * @return array{string, string}
     */
    private static function ends(string $pattern): array
    {
        return [\substr($pattern, 0, (int) \strpos($pattern, '*')), \substr($pattern, (int) \strrpos($pattern, '*') + 1)];
    }
}
