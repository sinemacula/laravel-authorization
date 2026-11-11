<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Exceptions\GuardrailException;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * The rule a policy in use as a guardrail keeps (AUTHZ-7.6): it changes only
 * through the guardrail service, which checks who changes it, so it is neither
 * edited nor deleted, which would change or lift the cap past that check.
 *
 * The policy observer refuses an edit or a deletion of such a policy with
 * `GuardrailException`, naming every scope it is a guardrail on, and counting
 * the guardrail rows naming half a tenant as malformed, never as the platform
 * or a tenant, until each guardrail is removed through the guardrail service, a
 * malformed row with the policy's guardrail on the platform; the table's
 * foreign key refuses a deletion made past the model. A policy not yet saved is
 * a guardrail nowhere, and passes without a query.
 *
 * The policy's row is locked before its guardrails are read, as the guardrail
 * service locks it before setting one, so an edit and a guardrail set at the
 * same moment are serialised: the edit is refused once the guardrail is there,
 * and a guardrail set after the edit weighs the document as edited.
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

        // The policy's row is locked first, as the guardrail service locks it
        // before setting a guardrail, so a guardrail set at the same moment is
        // either committed before the read below, which sees it, or waits until
        // this change is done.
        InlinePolicies::storedForUpdate($policy->getKey());

        [$tenants, $malformed] = self::scopes($policy);

        if ($tenants === [] && $malformed === 0) {
            return;
        }

        throw GuardrailException::inUse(PolicyDocument::nameOf($policy->getAttribute('name')), $tenants, $change, $malformed);
    }

    /**
     * Return every scope the policy is a guardrail on, each a tenant or null
     * for the platform, the platform first and then the tenants in a fixed
     * order, and how many of its guardrail rows name half a tenant, which are
     * neither the platform's nor any tenant's (see `TenantColumns`), by a
     * locking read, so a guardrail another transaction committed since this one
     * began is seen, as a plain read of a MySQL snapshot would not see it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return array{list<\SineMacula\Laravel\Authorization\Support\Reference|null>, int}
     */
    private static function scopes(Policy $policy): array
    {
        $table     = TableNames::get('guardrails');
        $query     = AuthorizationConnection::connection()->table($table)->useWritePdo()->where('policy_id', $policy->getKey())->sharedLock();
        $tenants   = [];
        $malformed = 0;

        // The platform's first, then by tenant.
        $query->orderByRaw('case when tenant_type is null and tenant_id is null then 0 else 1 end')->orderBy('tenant_type')->orderBy('tenant_id');

        foreach ($query->get(['tenant_type', 'tenant_id']) as $row) {
            /** @var array{tenant_type: string|null, tenant_id: int|string|null} $columns */
            $columns = (array) $row;

            if (TenantColumns::isHalf($columns['tenant_type'], $columns['tenant_id'])) {
                $malformed++;

                continue;
            }

            $tenants[] = $columns['tenant_type'] === null ? null : new Reference($columns['tenant_type'], (string) $columns['tenant_id']);
        }

        return [$tenants, $malformed];
    }
}
