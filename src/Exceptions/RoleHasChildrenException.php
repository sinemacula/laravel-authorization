<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a role with children would be deleted (D18). Deleting it would
 * take from everyone holding a child what the role passed down, so the children
 * are moved to another parent or deleted first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RoleHasChildrenException extends \LogicException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $roleName
     * @param  list<string>  $childNames
     */
    public function __construct(

        /** The name of the role refused. */
        private readonly string $roleName,

        /** The names of its children. */
        private readonly array $childNames,
    ) {
        parent::__construct(
            "Role '{$roleName}' has children (" . \implode(', ', \array_map(static fn (string $name): string => "'{$name}'", $childNames)) . ')'
                . ' and cannot be deleted; move them to another parent or delete them first.',
        );
    }

    /**
     * Return the name of the role refused.
     *
     * @return string
     */
    public function getRoleName(): string
    {
        return $this->roleName;
    }

    /**
     * Return the names of its children.
     *
     * @return list<string>
     */
    public function getChildNames(): array
    {
        return $this->childNames;
    }
}
