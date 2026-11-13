<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Policy;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Enums\MutationOperation;
use SineMacula\Laravel\Authorization\Events\Concerns\DescribesRecordChange;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched once a policy is deleted, and with it every attachment of it.
 *
 * `grantees` lists every grantee the policy was attached to, in any scope and
 * whether or not the attachment had expired, read inside the delete's
 * transaction before the row was removed, so the evidence says who lost access.
 *
 * A snapshot of plain values, never a model. It is dispatched once the write
 * commits, on the package's connection, and never for a write that rolls back
 * or changes nothing.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Deleted implements AuthorizationMutation
{
    use DescribesRecordChange;

    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $policy
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\DocumentDigest  $document
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The policy. */
        public Reference $policy,

        /** The policy's name. */
        public string $name,

        /** The tenant that owns the policy; null for the platform. */
        public ?Reference $tenant,

        /** The deleted document's version and digest. */
        public DocumentDigest $document,

        /** Every grantee the policy was attached to. */
        public array $grantees,
    ) {}

    /**
     * Return the stable identifier of the change: `policy.deleted`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::POLICY_DELETED->value;
    }

    /**
     * Return the policy the change is about.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    #[\Override]
    public function subject(): Reference
    {
        return $this->policy;
    }

    /**
     * Return every grantee that held the policy.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function grantees(): array
    {
        return $this->grantees;
    }
}
