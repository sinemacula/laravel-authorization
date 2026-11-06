<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Thrown when a role would take a permission or a parent role that another
 * tenant owns. A role takes only the platform's, its own tenant's and its
 * tenant's ancestors', so a platform role takes only the platform's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class OwnerMismatchException extends \InvalidArgumentException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $roleName
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $roleOwner
     * @param  string  $relatedKind
     * @param  string  $relatedName
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $relatedOwner
     */
    public function __construct(

        /** The role's name. */
        private readonly string $roleName,

        /** The tenant that owns the role; null for the platform. */
        private readonly ?Reference $roleOwner,

        /** What the role would take: `permission` or `parent role`. */
        private readonly string $relatedKind,

        /** The name of the permission or parent role. */
        private readonly string $relatedName,

        /** The tenant that owns the permission or parent role. */
        private readonly Reference $relatedOwner,
    ) {
        parent::__construct(
            "Role '{$roleName}', " . self::owner($roleOwner) . ", cannot take {$relatedKind} '{$relatedName}', " . self::owner($relatedOwner)
                . ': a role takes only the platform\'s and its own tenant\'s.',
        );
    }

    /**
     * Return the role's name.
     *
     * @return string
     */
    public function getRoleName(): string
    {
        return $this->roleName;
    }

    /**
     * Return the tenant that owns the role, or null for the platform.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function getRoleOwner(): ?Reference
    {
        return $this->roleOwner;
    }

    /**
     * Return what the role would take: `permission` or `parent role`.
     *
     * @return string
     */
    public function getRelatedKind(): string
    {
        return $this->relatedKind;
    }

    /**
     * Return the name of the permission or parent role.
     *
     * @return string
     */
    public function getRelatedName(): string
    {
        return $this->relatedName;
    }

    /**
     * Return the tenant that owns the permission or parent role.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    public function getRelatedOwner(): Reference
    {
        return $this->relatedOwner;
    }

    /**
     * Describe an owner for the message.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $owner
     * @return string
     */
    private static function owner(?Reference $owner): string
    {
        return $owner === null ? 'owned by the platform' : "owned by tenant '{$owner->type}:{$owner->id}'";
    }
}
