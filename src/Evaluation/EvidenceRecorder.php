<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Collects, while one explained check is decided, where each grant it may be
 * allowed by came from (N89): the provenance of every policy gathered for it,
 * as the grant resolution read it, and of the permission held, when the allow
 * stage asks for it. Once the check is decided, it gives the evidence of the
 * grants that allowed it (see `evidenceFor()`), and nothing is read again.
 *
 * A policy whose source cannot say how it reached the subject, a custom policy
 * resolver or a policy store, is recorded as `unavailable`; a policy attached
 * to the resource is named by the resource it is attached to. One recorder
 * serves one check, and only the explained check itself, never a further check
 * its administration stage makes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EvidenceRecorder
{
    /** @var array<string, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>> Where each policy gathered came from, by the policy's stored key, or its name for one built in code. */
    private array $policies = [];

    /** @var list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance> Where the permission held came from; empty until the allow stage finds one. */
    private array $permission = [];

    /**
     * Note the policies gathered from a grantee, the principal or its identity,
     * with where each came from, by its stored key, or with none when the
     * source cannot say, which records each as `unavailable`.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  array<string, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>>|null  $provenance
     * @param  object|null  $grantee
     * @param  bool  $isIdentity
     * @return void
     */
    public function notePolicies(array $policies, ?array $provenance, ?object $grantee = null, bool $isIdentity = false): void
    {
        foreach ($policies as $policy) {
            $key   = self::keyOf($policy->id, $policy->name);
            $name  = self::nameOf($policy->name, $policy->id);
            $found = $provenance[$policy->id ?? ''] ?? [GrantProvenance::unavailable($name, self::referenceTo($grantee), $isIdentity)];

            $this->policies[$key] = [...$this->policies[$key] ?? [], ...\array_map(static fn (GrantProvenance $grant): GrantProvenance => $grant->named($name), $found)];
        }
    }

    /**
     * Note the permission the allow stage found held, with where it came from,
     * and return it, as the allow stage asks for it.
     *
     * @param  array{string|null, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>}  $held
     * @return string|null
     */
    public function notePermission(array $held): ?string
    {
        $this->permission = $held[1];

        return $held[0];
    }

    /**
     * Return the evidence of the grants that allowed the decision: where the
     * policy of each statement that decided it came from, or where the
     * permission held came from; none for a denial.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Evaluation\DecisionEvidence
     */
    public function evidenceFor(Decision $decision): DecisionEvidence
    {
        if (!$decision->isAllowed()) {
            return new DecisionEvidence;
        }

        if ($decision->statements === []) {
            return new DecisionEvidence($this->permission);
        }

        $grants = [];

        foreach ($decision->statements as $statement) {
            $grants = [...$grants, ...$this->statementGrants($statement)];
        }

        return new DecisionEvidence($grants);
    }

    /**
     * Return where the policy of the statement came from: the resource its
     * policy is attached to, for a resource policy, else what was noted for the
     * policy, or `unavailable` when nothing was.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $statement
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>
     */
    private function statementGrants(StatementReference $statement): array
    {
        $name = self::nameOf($statement->policy, $statement->policyId);

        if ($statement->resource !== null) {
            return [new GrantProvenance(Enums\GrantSource::RESOURCE_POLICY, $name . ' on ' . $statement->resource)];
        }

        return $this->policies[self::keyOf($statement->policyId, $statement->policy)] ?? [GrantProvenance::unavailable($name)];
    }

    /**
     * Return the key a policy is noted by: its stored key, or its name for one
     * built in code.
     *
     * @param  string|null  $id
     * @param  string  $name
     * @return string
     */
    private static function keyOf(?string $id, string $name): string
    {
        return $id === null ? "name:{$name}" : "id:{$id}";
    }

    /**
     * Return a policy as a grant names it: its name, with its stored key when
     * it has one, `name[key]`.
     *
     * @param  string  $name
     * @param  string|null  $id
     * @return string
     */
    private static function nameOf(string $name, ?string $id): string
    {
        return $id === null ? $name : "{$name}[{$id}]";
    }

    /**
     * Return the reference to a grantee that is a saved model, or null.
     *
     * @param  object|null  $grantee
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    private static function referenceTo(?object $grantee): ?Reference
    {
        return $grantee instanceof Model && $grantee->exists ? Reference::of($grantee) : null;
    }
}
