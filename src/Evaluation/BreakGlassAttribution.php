<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\HeldPermissions;

/**
 * The break-glass activations behind the allow of one check (N142), found from
 * what the resolution cache keeps beside the principal's permissions, policies
 * and role keys (see `ResolutionCache::activationsOf()`), so a check names them
 * with no query.
 *
 * The decision pipeline builds one with a check's sources, and notes the
 * principal's policies as they resolve, before the resource's and the
 * guardrails' are read in their own scope, and its permissions as the allow
 * stage asks for them, so no scope the check passes through loses them. An
 * allow a permission held made names the activations behind every permission of
 * the principal's that covers the action. One statements made names those
 * behind each policy of theirs attached to the principal, and, for a resource
 * policy's statement, those behind each role its selectors name, unless one
 * names the subject by reference. Only the principal's own roles can come
 * through an activation, so a machine, an identity and a check while
 * break-glass is disabled get no attribution, and a denial names none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BreakGlassAttribution
{
    /** @var array<string, list<string>> The activations behind each of the principal's permissions, by name, as the check read them. */
    private array $permissions = [];

    /** @var array<string, list<string>> The activations behind each of the principal's policies, by key, as the check read them. */
    private array $policies = [];

    /**
     * Create the attribution of one check.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     */
    private function __construct(

        /** The resolution cache the activations are kept in. */
        private readonly ResolutionCache $cache,

        /** The subject of the check. */
        private readonly Subject $subject,

        /** The action checked. */
        private readonly string $action,
    ) {}

    /**
     * Return the attribution of a check of the action, or null when no
     * activation of the subject's principal can count.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @return self|null
     */
    public static function of(Subject $subject, string $action): ?self
    {
        $cache = BreakGlassActivations::isCounted($subject->subject) ? ResolutionCache::instance() : null;

        return $cache === null ? null : new self($cache, $subject, $action);
    }

    /**
     * Keep the activations behind the principal's policies, as just resolved.
     *
     * @return void
     */
    public function notePolicies(): void
    {
        $this->policies = $this->cache->activationsOf('policies', $this->subject->subject);
    }

    /**
     * Keep the activations behind the principal's permissions, as just
     * resolved, and return the permission held.
     *
     * @param  string|null  $held
     * @return string|null
     */
    public function notePermission(?string $held): ?string
    {
        $this->permissions = $this->cache->activationsOf('permissions', $this->subject->subject);

        return $held;
    }

    /**
     * Return the keys of the activations behind the decision, weighed from the
     * policies given; none for a denial or an allow no activation gave.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<string>
     */
    public function behind(Decision $decision, array $policies): array
    {
        return match (true) {
            !$decision->isAllowed()      => [],
            $decision->statements === [] => $this->behindPermission($decision),
            default                      => $this->behindStatements($decision->statements, $policies),
        };
    }

    /**
     * Return the activations behind each permission of the principal's that
     * covers the action, for an allow whose last step names a permission held.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return list<string>
     */
    private function behindPermission(Decision $decision): array
    {
        if ($decision->trace === [] || $decision->trace[\array_key_last($decision->trace)]->permission === null) {
            return [];
        }

        $covering = \array_filter($this->permissions, fn (string $name): bool => HeldPermissions::match([$name], $this->action) !== null, \ARRAY_FILTER_USE_KEY);

        return \array_merge(...\array_values($covering));
    }

    /**
     * Return the activations behind the statements that allowed the decision.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>  $statements
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<string>
     */
    private function behindStatements(array $statements, array $policies): array
    {
        $keys = [];

        foreach ($statements as $statement) {
            \array_push($keys, ...($statement->resource !== null
                ? $this->behindSelectors($statement, $policies)
                : $this->policies[$statement->policyId ?? ''] ?? []));
        }

        return $keys;
    }

    /**
     * Return the activations behind the roles a resource policy's statement
     * names the subject by, as its allow read the principal's role keys.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $statement
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<string>
     */
    private function behindSelectors(StatementReference $statement, array $policies): array
    {
        $roles     = $this->cache->activationsOf('role-keys', $this->subject->subject);
        $selectors = $roles === [] ? [] : self::selectorsOf($statement, $policies);
        $keys      = [];

        foreach ($selectors === [] ? [] : (new PrincipalSelectors($this->subject))->rolesNaming($selectors) as $role) {
            \array_push($keys, ...$roles[$role] ?? []);
        }

        return $keys;
    }

    /**
     * Return the `principals` selectors of the statement among the policies.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $statement
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return array<int, string>
     */
    private static function selectorsOf(StatementReference $statement, array $policies): array
    {
        foreach ($policies as $policy) {
            if ($policy->id === $statement->policyId && $policy->resource === $statement->resource) {
                return $policy->statements[$statement->index]->principals ?? [];
            }
        }

        return [];
    }
}
