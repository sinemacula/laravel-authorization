<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The grant or removal an operation resource proposes, as values: who it is
 * for, what it hands out or takes away, where it holds and until when, and
 * whether it changes nothing. The administration stage weighs these (see
 * `OperationConstraints`); policies read the same as the operation resource's
 * attributes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OperationChange
{
    /** @var \Illuminate\Support\Carbon|null When the grant expires, in UTC; null for one that never does. */
    public ?Carbon $expiresAt;

    /**
     * Create a new operation change.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model|null  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  bool  $isUnchanged
     */
    public function __construct(

        /** The identity, principal or role the change is for, or the resource a policy is attached to. */
        public Reference $grantee,

        /** The role, permission or policy handed out or taken away; null for a call that names none. */
        public ?Model $target,

        /** Where the grant holds: its tenant, application and reach. */
        public GrantScope $scope,

        // When the grant expires, in any zone; null for one that never does.
        ?\DateTimeInterface $expiresAt = null,

        /** Whether the change changes nothing. */
        public bool $isUnchanged = false,
    ) {
        $this->expiresAt = UtcDateTime::toUtc($expiresAt);
    }

    /**
     * Return the Unix time the grant lasts until, or `PHP_INT_MAX` for one that
     * never expires, so a lifetime that must cover it is compared as one
     * number.
     *
     * @return int
     */
    public function lastsUntil(): int
    {
        return $this->expiresAt?->getTimestamp() ?? \PHP_INT_MAX;
    }
}
