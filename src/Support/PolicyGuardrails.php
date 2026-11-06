<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Exceptions\GuardrailException;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * The rule a policy in use as a guardrail keeps (AUTHZ-7.6): it changes only
 * through the guardrail service, which checks who changes it, so it is neither
 * edited nor deleted, which would change or lift the cap past that check.
 *
 * The policy observer refuses an edit or a deletion of such a policy with
 * `GuardrailException`, naming every scope it is a guardrail on, until each
 * guardrail is removed through the guardrail service; the table's foreign key
 * refuses a deletion made past the model. A policy not yet saved is a guardrail
 * nowhere, and passes without a query.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PolicyGuardrails
{
    /**
     * Refuse to edit the policy while it is a guardrail anywhere, read on the
     * write connection.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardrailException
     */
    public static function assertEditable(Policy $policy): void
    {
        self::assertUnused($policy, 'editing');
    }

    /**
     * Refuse to delete the policy while it is a guardrail anywhere, read on the
     * write connection.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardrailException
     */
    public static function assertDeletable(Policy $policy): void
    {
        self::assertUnused($policy, 'deleting');
    }

    /**
     * Refuse the change while the policy is a guardrail anywhere.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  string  $change
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardrailException
     */
    private static function assertUnused(Policy $policy, string $change): void
    {
        if (!$policy->exists) {
            return;
        }

        $tenants = self::scopes($policy);

        if ($tenants === []) {
            return;
        }

        throw GuardrailException::inUse(PolicyDocument::nameOf($policy->getAttribute('name')), $tenants, $change);
    }

    /**
     * Return every scope the policy is a guardrail on, each a tenant or null
     * for the platform, the platform first and then the tenants in a fixed
     * order.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference|null>
     */
    private static function scopes(Policy $policy): array
    {
        /** @var string $table */
        $table   = config('authorization.tables.guardrails', 'guardrails');
        $query   = AuthorizationConnection::connection()->table($table)->useWritePdo()->where('policy_id', $policy->getKey());
        $tenants = [];

        // The platform's first, then by tenant.
        $query->orderByRaw('case when tenant_type is null then 0 else 1 end')->orderBy('tenant_type')->orderBy('tenant_id');

        foreach ($query->get(['tenant_type', 'tenant_id']) as $row) {
            /** @var array{tenant_type: string|null, tenant_id: int|string|null} $columns */
            $columns   = (array) $row;
            $tenants[] = $columns['tenant_type'] === null ? null : new Reference($columns['tenant_type'], (string) $columns['tenant_id']);
        }

        return $tenants;
    }
}
