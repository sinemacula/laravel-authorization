<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a row is saved with an inconsistent pair of tenant ownership
 * columns — only one of `tenant_type` / `tenant_id` set.
 *
 * Both-or-neither is the invariant: a row is either global (both columns null)
 * or tenant-owned (both columns non-null). A half- set pair would be silently
 * invisible to both the `TenantScope::apply` global filter and any
 * `scopeForTenant` / `scopeGlobalOnly` local scope — orphaned data from the
 * caller's point of view. The model `saving` hook raises this exception before
 * the row reaches the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidTenantColumnsException extends \LogicException
{
    /**
     * Create a new exception instance describing the offending model kind (role
     * / permission) and which column is missing.
     *
     * @param  string  $modelKind
     * @param  string  $missingColumn
     */
    public function __construct(string $modelKind, string $missingColumn)
    {
        parent::__construct(\sprintf(
            'Cannot save %s with inconsistent tenant columns — \'%s\' is required when the other tenant column is set. '
            . 'Both columns must be null (global row) or both must be non-null (tenant-owned row).',
            $modelKind,
            $missingColumn,
        ));
    }
}
