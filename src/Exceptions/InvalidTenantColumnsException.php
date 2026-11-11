<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a row is saved with an inconsistent pair of tenant ownership
 * columns — only one of `tenant_type` / `tenant_id` set.
 *
 * Both-or-neither is the invariant: a row is either global (both columns null)
 * or tenant-owned (both columns non-null). A half-set pair belongs to neither
 * the platform nor a tenant, for a role, a permission or a policy alike; for
 * roles and permissions it would also be invisible to the `TenantScope::apply`
 * global filter, orphaned data from the caller's point of view. The model
 * `saving` hook raises this exception before the row reaches the database, and
 * a grant of a row stored that way, which the package never writes, is refused
 * with it too, in every scope, since no tenant owns it and the platform does
 * not either.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidTenantColumnsException extends \LogicException
{
    /**
     * Create a new exception instance describing the offending model kind
     * (role, permission or policy), which column is missing, and what was
     * refused: saving the row, or granting a row stored that way.
     *
     * @param  string  $modelKind
     * @param  string  $missingColumn
     * @param  string  $action
     */
    public function __construct(string $modelKind, string $missingColumn, string $action = 'save')
    {
        parent::__construct(\sprintf(
            'Cannot %s %s with inconsistent tenant columns — \'%s\' is required when the other tenant column is set. '
            . 'Both columns must be null (global row) or both must be non-null (tenant-owned row).',
            $action,
            $modelKind,
            $missingColumn,
        ));
    }
}
