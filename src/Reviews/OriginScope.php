<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Where a stored row a review lists holds, as its columns store it: its
 * tenant's type and key, its application and whether it reaches the tenants
 * below.
 *
 * A row names a whole tenant, both its type and its key, or none, the platform.
 * A row that names half a tenant, a type without a key or a key without a type,
 * which the package never writes, keeps the half it names, so a review never
 * presents it as the platform's (see `isMalformed()` and
 * `Enums\GrantState::MALFORMED`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OriginScope
{
    /**
     * Create a new origin scope.
     *
     * @param  string|null  $tenantType
     * @param  string|null  $tenantId
     * @param  string|null  $application
     * @param  bool  $includeSubtree
     */
    public function __construct(

        /** The stored type of the row's tenant; null when none is stored. */
        public ?string $tenantType,

        /** The stored key of the row's tenant; null when none is stored. */
        public ?string $tenantId,

        /** The application the row holds in; null for every application. */
        public ?string $application,

        /** Whether the row reaches the tenants below its tenant. */
        public bool $includeSubtree,
    ) {}

    /**
     * Return the origin scope of a grant scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return self
     */
    public static function of(GrantScope $scope): self
    {
        return new self($scope->tenant?->type, $scope->tenant?->id, $scope->application, $scope->includeSubtree);
    }

    /**
     * Return the tenant the row names whole, or null for the platform and for a
     * row naming half a tenant.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function tenant(): ?Reference
    {
        return $this->tenantType === null || $this->tenantId === null ? null : new Reference($this->tenantType, $this->tenantId);
    }

    /**
     * Determine whether the row names half a tenant: a type without a key, or a
     * key without a type.
     *
     * @return bool
     */
    public function isMalformed(): bool
    {
        return ($this->tenantType === null) !== ($this->tenantId === null);
    }

    /**
     * Return the scope as plain values: its tenant's type and key as stored, or
     * null when neither is, its application, null for every application, and
     * whether it reaches the tenants below.
     *
     * @return array{tenant: array{type: string|null, id: string|null}|null, application: string|null, include_subtree: bool}
     */
    public function toArray(): array
    {
        $isPlatform = $this->tenantType === null && $this->tenantId === null;

        return [
            'tenant'          => $isPlatform ? null : ['type' => $this->tenantType, 'id' => $this->tenantId],
            'application'     => $this->application,
            'include_subtree' => $this->includeSubtree,
        ];
    }
}
