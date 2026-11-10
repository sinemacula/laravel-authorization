<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * The rule a policy's `principals` keep about where the policy is attached
 * (AUTHZ-7.3).
 *
 * A policy attached to a resource or a resource type is managed, and each of
 * its allow statements names its principals; a policy attached to a grantee or
 * a role names none. The policy document's shape, a deny taking no principals
 * included, is validated when it is written (see `StatementValidator`); this
 * holds the attachment to the rule: the resource policy service refuses a
 * policy that breaks it for a resource, the grant service and a write through a
 * grantee's `policies()` relation one that breaks it for a grantee, each
 * reading the stored row, and the policy observer refuses a rewrite of an
 * attached policy that would break it for where the policy is attached.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PolicyPrincipals
{
    /**
     * Refuse to attach the policy, as stored, to a resource: an inline policy,
     * or one with an allow statement that names no principals.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $stored
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException
     */
    public static function assertAttachableToResource(Policy $stored): void
    {
        $name = PolicyDocument::nameOf($stored->getAttribute('name'));

        if (InlinePolicies::ownerOf($stored) !== null) {
            throw ResourcePolicyException::inline($name);
        }

        $unnamed = self::allowsWithoutPrincipals($stored);

        if ($unnamed !== []) {
            throw ResourcePolicyException::principalsRequired($name, $unnamed);
        }
    }

    /**
     * Refuse to attach the policy, as stored, to a grantee or a role when any
     * statement names principals.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $stored
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException
     */
    public static function assertAttachableToGrantee(Policy $stored): void
    {
        $named = self::withPrincipals($stored);

        if ($named !== []) {
            throw ResourcePolicyException::principalsRefused(PolicyDocument::nameOf($stored->getAttribute('name')), $named);
        }
    }

    /**
     * Refuse a rewrite of a saved policy's document that breaks the rule for
     * where the policy is attached: principals while it is attached to a
     * grantee or a role, or set as a grantee's boundary, or an allow naming
     * none while it is attached to a resource. A policy not yet saved, or whose
     * document is unchanged, is attached nowhere new, and passes without a
     * query.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException
     */
    public static function assertRewritable(Policy $policy): void
    {
        if (!$policy->exists || !$policy->isDirty('document')) {
            return;
        }

        if (self::withPrincipals($policy) !== [] && (self::isAttachedIn('authorizable_policies', $policy) || PolicyBoundaries::isBoundary($policy))) {
            self::assertAttachableToGrantee($policy);
        }

        if (self::allowsWithoutPrincipals($policy) === [] || !self::isAttachedIn('resource_policies', $policy)) {
            return;
        }

        self::assertAttachableToResource($policy);
    }

    /**
     * Return the positions of the policy's allow statements that name no
     * principals.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return list<int>
     */
    private static function allowsWithoutPrincipals(Policy $policy): array
    {
        $unnamed = static fn (array $statement): bool => ($statement['effect'] ?? null) === PolicyEffect::ALLOW->value && !isset($statement['principals']);

        return \array_keys(\array_filter(self::statementsOf($policy), $unnamed));
    }

    /**
     * Return the positions of the policy's statements that name principals.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return list<int>
     */
    private static function withPrincipals(Policy $policy): array
    {
        return \array_keys(\array_filter(self::statementsOf($policy), static fn (array $statement): bool => \array_key_exists('principals', $statement)));
    }

    /**
     * Return the statements of the policy's document, each as an array, by
     * position; none when the document holds no list of statements.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return array<int, array<array-key, mixed>>
     */
    private static function statementsOf(Policy $policy): array
    {
        $document   = $policy->getAttribute('document');
        $statements = \is_array($document) && \is_array($document['statements'] ?? null) ? $document['statements'] : [];

        return \array_filter(\array_values($statements), \is_array(...));
    }

    /**
     * Determine whether the policy is attached through the table the
     * configuration names under the key, read on the write connection.
     *
     * @param  string  $table
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return bool
     */
    private static function isAttachedIn(string $table, Policy $policy): bool
    {
        $name = TableNames::get($table);

        return AuthorizationConnection::connection()->table($name)->useWritePdo()->where('policy_id', $policy->getKey())->exists();
    }
}
