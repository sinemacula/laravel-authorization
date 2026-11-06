<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Thrown when a role, permission or policy one tenant owns would be granted
 * anywhere but in that tenant or a tenant below it: platform-wide, or in a
 * tenant outside its subtree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GrantScopeMismatchException extends \InvalidArgumentException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $kind
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $owner
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $scope
     */
    public function __construct(

        /** The kind of record: `role`, `permission` or `policy`. */
        private readonly string $kind,

        /** The record's name. */
        private readonly string $name,

        /** The tenant that owns the record. */
        private readonly Reference $owner,

        /** The tenant the grant would hold in; null for platform-wide. */
        private readonly ?Reference $scope,
    ) {
        parent::__construct(
            "The {$kind} '{$name}' belongs to tenant '{$owner->type}:{$owner->id}' and can only be granted there or in a tenant below it, not "
                . ($scope === null ? 'platform-wide' : "in tenant '{$scope->type}:{$scope->id}'") . '.',
        );
    }

    /**
     * Return the kind of record refused.
     *
     * @return string
     */
    public function getKind(): string
    {
        return $this->kind;
    }

    /**
     * Return the name of the record refused.
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Return the tenant that owns the record.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    public function getOwner(): Reference
    {
        return $this->owner;
    }

    /**
     * Return the tenant the grant would have held in, or null for
     * platform-wide.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function getScope(): ?Reference
    {
        return $this->scope;
    }
}
