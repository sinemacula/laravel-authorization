<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Hooks;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * One grant a call proposes to write, as a grant hook sees it (AUTHZ-11.3): the
 * action it falls under, what it grants, where it holds, until when, and why it
 * widens the identity's scope.
 *
 * It is an immutable value: it names the role, permission or policy granted by
 * reference, never as a model, and its expiry is an immutable instant in UTC,
 * so a hook can neither change the grant through it nor read anything the grant
 * does not say.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProposedGrant
{
    /**
     * Create a new proposed grant.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @param  bool  $includeSubtree
     * @param  \DateTimeImmutable|null  $expiresAt
     * @param  list<\SineMacula\Laravel\Authorization\Enums\WideningReason>  $reasons
     */
    public function __construct(

        /** The action the grant falls under, such as `authorization:role.grant`. */
        public string $action,

        /** The role, permission or policy granted. */
        public Reference $target,

        /** The tenant the grant holds in, or null for platform-wide. */
        public ?Reference $tenant,

        /** The application the grant holds in, or null for every application. */
        public ?string $application,

        /** Whether the grant also holds in the tenants below its tenant. */
        public bool $includeSubtree,

        /** When the grant expires, in UTC, or null for never. */
        public ?\DateTimeImmutable $expiresAt,

        /** Why the grant widens the identity's scope, none before it is classified. */
        public array $reasons = [],
    ) {}

    /**
     * Return the proposed grant of the target of the kind, in the scope, until
     * the expiry, not yet classified.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \DateTimeInterface|null  $expiresAt
     * @return self
     *
     * @internal
     */
    public static function of(GrantTarget $kind, Model $target, GrantScope $scope, ?\DateTimeInterface $expiresAt): self
    {
        $expiry = $expiresAt === null ? null : CarbonImmutable::instance($expiresAt)->utc();

        return new self($kind->grantAction(), Reference::of($target), $scope->tenant, $scope->application, $scope->includeSubtree, $expiry);
    }

    /**
     * Return this grant with the reasons it widens the identity's scope.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Enums\WideningReason>  $reasons
     * @return self
     */
    public function withReasons(array $reasons): self
    {
        return new self($this->action, $this->target, $this->tenant, $this->application, $this->includeSubtree, $this->expiresAt, $reasons);
    }

    /**
     * Return the key the grant is told apart by: everything it proposes, its
     * reasons left out, so the same grant classified twice has one key.
     *
     * @return string
     */
    public function key(): string
    {
        return \serialize([
            $this->action,
            $this->target->type,
            $this->target->id,
            $this->tenant?->type,
            $this->tenant?->id,
            $this->application,
            $this->includeSubtree,
            $this->expiresAt?->getTimestamp(),
        ]);
    }
}
