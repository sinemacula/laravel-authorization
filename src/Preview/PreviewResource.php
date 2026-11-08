<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Preview;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The resource a preview's admission is decided on (AUTHZ-11.4, N84): the
 * subject previewed, by references to its principal and to the identity behind
 * it, and the scope one of the target's decisions is made in, its tenant and
 * application, and whether it is decided just below that tenant.
 *
 * Its reference is a record of type `authorization:preview` whose id is the
 * principal's morph type and key (`user:42`), so a statement's resource pattern
 * can name the targets a previewer may preview
 * (`authorization:preview:user:*`), and whose tenant is the scope's tenant,
 * never the tenant the request is in. Each admission is decided with that scope
 * in place, the tenant, or the platform, and the application (see
 * `PreviewAdmission`), so the resource is decided as any resource of the tenant
 * in place is (see `ResourceScope`): in the tenant, or just below it when the
 * decision is, where the previewer's grants and denies reaching the tenant
 * count, and, with no tenant, at platform scope, where only a platform-wide
 * grant of the right counts. The reference hands the resource on as its source,
 * so the package's attribute provider (see `PreviewAttributes`) offers its
 * attributes to policies under `resource`.
 *
 * It names references and names alone, never a model, a session or a value of
 * the target's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PreviewResource implements AuthorizableResource
{
    /** @var string The morph type of every preview resource. */
    public const string TYPE = 'authorization:preview';

    /**
     * Create a new preview resource.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $identity
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @param  bool  $isBelow
     */
    public function __construct(

        /** The principal previewed. */
        public Reference $target,

        /** The identity behind the principal previewed; null when it has none that is a saved record. */
        public ?Reference $identity,

        /** The tenant the preview is made in; null for the platform. */
        public ?Reference $tenant,

        /** The application the preview is made in; null for none. */
        public ?string $application,

        /** Whether the decision is made just below the tenant, where only a grant that reaches the tenants below it counts. */
        public bool $isBelow = false,
    ) {}

    /**
     * Return the preview of the same target in the scope given: the tenant, or
     * none for the platform, the application, and whether it is decided just
     * below the tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @param  bool  $isBelow
     * @return self
     */
    public function in(?Reference $tenant, ?string $application, bool $isBelow): self
    {
        return new self($this->target, $this->identity, $tenant, $application, $isBelow);
    }

    /**
     * Return what the preview names, as the package's attribute provider offers
     * it under `resource`: the principal and the identity previewed, by morph
     * type and key, and the application; a key with no value is left out.
     *
     * @return array<string, string>
     */
    public function attributes(): array
    {
        $attributes = [
            'target_type'   => $this->target->type,
            'target_id'     => $this->target->id,
            'identity_type' => $this->identity?->type,
            'identity_id'   => $this->identity?->id,
            'application'   => $this->application,
        ];

        return \array_filter($attributes, static fn (?string $value): bool => $value !== null);
    }

    /**
     * Return the reference to the preview: a record of the preview type, keyed
     * by the principal previewed, in the scope's tenant, handing this resource
     * on as its source.
     *
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    #[\Override]
    public function toResourceReference(): ResourceReference
    {
        $id = $this->target->type . ':' . $this->target->id;

        return new ResourceReference(self::TYPE . ':' . $id, self::TYPE, $id, $this->tenant, null, $this);
    }
}
