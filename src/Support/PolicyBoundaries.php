<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Exceptions\BoundaryException;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * The rule a policy in use as a permission boundary keeps (AUTHZ-7.4): it is
 * never deleted from under a grantee it bounds, which would lift the cap
 * without a word.
 *
 * The policy observer refuses the deletion of such a policy with
 * `BoundaryException`, naming every grantee it bounds, until each boundary is
 * removed through the boundary service; the table's foreign key refuses a
 * deletion made past the model. A policy not yet saved bounds no one, and
 * passes without a query.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PolicyBoundaries
{
    /**
     * Refuse to delete the policy while it is the boundary of any grantee, read
     * on the write connection.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\BoundaryException
     */
    public static function assertDeletable(Policy $policy): void
    {
        if (!$policy->exists) {
            return;
        }

        $grantees = self::bounded($policy);

        if ($grantees === []) {
            return;
        }

        throw BoundaryException::inUse(PolicyDocument::nameOf($policy->getAttribute('name')), $grantees);
    }

    /**
     * Determine whether the policy is the boundary of any grantee, read on the
     * write connection.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return bool
     */
    public static function isBoundary(Policy $policy): bool
    {
        return self::query($policy)->exists();
    }

    /**
     * Return every grantee the policy is the boundary of, each once, in a fixed
     * order.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private static function bounded(Policy $policy): array
    {
        $grantees = [];

        foreach (self::query($policy)->orderBy('authorizable_type')->orderBy('authorizable_id')->get(['authorizable_type', 'authorizable_id']) as $row) {
            /** @var array{authorizable_type: string, authorizable_id: int|string} $columns */
            $columns = (array) $row;
            $key     = $columns['authorizable_type'] . "\0" . $columns['authorizable_id'];

            $grantees[$key] = new Reference($columns['authorizable_type'], (string) $columns['authorizable_id']);
        }

        return \array_values($grantees);
    }

    /**
     * Query the boundaries the policy is, on the write connection.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return \Illuminate\Database\Query\Builder
     */
    private static function query(Policy $policy): Builder
    {
        $table = TableNames::get('authorizable_boundaries');

        return AuthorizationConnection::connection()->table($table)->useWritePdo()->where('policy_id', $policy->getKey());
    }
}
