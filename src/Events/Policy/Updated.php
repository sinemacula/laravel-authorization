<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Policy;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Events\Concerns\DescribesRecordChange;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched once a policy is updated: renamed, described, rewritten or
 * otherwise changed.
 *
 * `changes` holds the fields the update changed other than the document:
 * `before` their values before it, `after` their values after it, as plain
 * values (dates as ISO 8601 strings in UTC). The document is never carried:
 * `document` is the version and digest of the document after the update, and
 * `previousDocument` those of the document before it when the update rewrote
 * it, else null.
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
final readonly class Updated implements AuthorizationMutation
{
    use DescribesRecordChange;

    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $policy
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  array{before: array<string, scalar|null>, after: array<string, scalar|null>}  $changes
     * @param  \SineMacula\Laravel\Authorization\Support\DocumentDigest  $document
     * @param  \SineMacula\Laravel\Authorization\Support\DocumentDigest|null  $previousDocument
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

        /** The changed fields other than the document, before and after. */
        public array $changes,

        /** The document's version and digest after the update. */
        public DocumentDigest $document,

        /** The previous document's version and digest, when rewritten. */
        public ?DocumentDigest $previousDocument,
    ) {}

    /**
     * Return the stable identifier of the change: `policy.updated`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return 'policy.updated';
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
