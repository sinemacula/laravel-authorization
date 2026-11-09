<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The resource a review's admission is decided on (AUTHZ-11.6, N96): the
 * question the review asks, what it is about, by references alone, and the
 * scope it reads.
 *
 * Its reference is a record of type `authorization:review` whose id is the
 * question (`holders`, `holdings`, `expiring` or `granted_by`), so a
 * statement's resource pattern can name the reviews a reviewer may run
 * (`authorization:review:holders`), and whose tenant is the reviewed tenant,
 * none for the platform and everywhere, never the tenant the request is in. The
 * reference hands the resource on as its source, so the package's attribute
 * provider (see `ReviewAttributes`) offers what it names to policies under
 * `resource`, and the decision's administration stage weighs its reach (see
 * `ReviewAdmission`).
 *
 * It names references and plain values alone, never a model, a row, a count or
 * a value of what is reviewed. When someone impersonates the reviewer, it names
 * the impersonator too, who is the one shown what the review discloses, so the
 * review is weighed as a delegated change made while impersonating is (see
 * `ReviewAdmission`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReviewResource implements AuthorizableResource
{
    /** @var string The morph type of every review resource. */
    public const string TYPE = 'authorization:review';

    /**
     * Create a new review resource.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind  $kind
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $impersonator
     */
    public function __construct(

        /** The question the review asks. */
        public ReviewKind $kind,

        /** The scope the review reads. */
        public ReviewScope $scope,

        /** The role, permission or policy whose holders are listed; null for none. */
        public ?Reference $target = null,

        /** The principal or identity whose holdings are listed; null for none. */
        public ?Reference $subject = null,

        /** The actor whose last grants are listed; null for none. */
        public ?Reference $actor = null,

        /** Who is impersonating the reviewer, or null when no one is. */
        public ?Reference $impersonator = null,
    ) {}

    /**
     * Return the resource of the review.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return self
     */
    public static function of(ReviewQuery $query): self
    {
        return new self($query->kind, $query->scope, $query->target, $query->about(), $query->actor);
    }

    /**
     * Return this resource of the review run while the impersonator, when there
     * is one, impersonates the reviewer.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $impersonator
     * @return self
     */
    public function actedBy(?Reference $impersonator): self
    {
        return new self($this->kind, $this->scope, $this->target, $this->subject, $this->actor, $impersonator);
    }

    /**
     * Return the reach the review is admitted across (see
     * `ReviewScope::reach()`).
     *
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    public function reach(): GrantScope
    {
        return $this->scope->reach();
    }

    /**
     * Return what the review names, as the package's attribute provider offers
     * it under `resource`: the question, the scope's selection, the selection
     * of its application and the application named, the target, subject and
     * actor by morph type and key, whether the reviewer is impersonated, and by
     * whom; a key with no value is left out.
     *
     * @return array<string, bool|string>
     */
    public function attributes(): array
    {
        $attributes = [
            'query'                 => $this->kind->value,
            'scope'                 => $this->scope->selection->value,
            'application_selection' => $this->scope->application->selection(),
            'application'           => $this->scope->application->application,
            'target_type'           => $this->target?->type,
            'target_id'             => $this->target?->id,
            'subject_type'          => $this->subject?->type,
            'subject_id'            => $this->subject?->id,
            'actor_type'            => $this->actor?->type,
            'actor_id'              => $this->actor?->id,
            'impersonated'          => $this->impersonator !== null,
            'impersonator_type'     => $this->impersonator?->type,
            'impersonator_id'       => $this->impersonator?->id,
        ];

        return \array_filter($attributes, static fn (bool|string|null $value): bool => $value !== null);
    }

    /**
     * Return the reference to the review: a record of the review type, keyed by
     * its question, in the reviewed tenant, handing this resource on as its
     * source.
     *
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    #[\Override]
    public function toResourceReference(): ResourceReference
    {
        return new ResourceReference(self::TYPE . ':' . $this->kind->value, self::TYPE, $this->kind->value, $this->scope->tenant, null, $this);
    }
}
