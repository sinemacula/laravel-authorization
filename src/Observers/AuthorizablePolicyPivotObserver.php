<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Observers;

use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePolicyPivot;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Row-lifecycle observer for the `AuthorizablePolicyPivot` model.
 *
 * Refuses an attachment of an inline policy to any grantee but the one it
 * belongs to when the row is written through a grantee's `policies()` relation
 * (`attach()`, `sync()` and the like), which saves the pivot model. The grant
 * service writes the table directly and refuses it itself, so the rule holds on
 * every write path the package offers.
 *
 * Registered via `#[ObservedBy(AuthorizablePolicyPivotObserver::class)]` on the
 * pivot model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthorizablePolicyPivotObserver
{
    /**
     * Refuse the row when it attaches an inline policy to a grantee it does not
     * belong to. A row naming no policy that exists is left to the foreign key.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePolicyPivot  $pivot
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException
     */
    public function saving(AuthorizablePolicyPivot $pivot): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class  = config('authorization.models.policy', Policy::class);
        $policy = $class::query()->withoutGlobalScopes()->find($pivot->getAttribute('policy_id'));

        if (!$policy instanceof Policy) {
            return;
        }

        InlinePolicies::assertAttachable($policy, new Reference(self::text($pivot->getAttribute('authorizable_type')), self::text($pivot->getAttribute('authorizable_id'))));
    }

    /**
     * Return a value read from the row as a string: a scalar as itself,
     * anything else as empty.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function text(mixed $value): string
    {
        return \is_scalar($value) ? (string) $value : '';
    }
}
