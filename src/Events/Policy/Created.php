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
 * Dispatched once a policy is created.
 *
 * The document is reported by its version and digest, never its statements.
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
final readonly class Created implements AuthorizationMutation
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
     * @param  bool  $isSystem
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

        /** The document's version and digest. */
        public DocumentDigest $document,

        /** Whether the policy is a system policy. */
        public bool $isSystem,
    ) {}

    /**
     * Return the stable identifier of the change: `policy.created`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::POLICY_CREATED->value;
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
}
