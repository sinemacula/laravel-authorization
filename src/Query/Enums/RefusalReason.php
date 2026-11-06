<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query\Enums;

/**
 * Why `whereAuthorized()` refused to scope a query (AUTHZ-10.2, N64): the scope
 * cannot prove that the rows it keeps are exactly those `check()` allows, so it
 * changes nothing and throws instead.
 *
 * Each code is lower-case letters and `_`, and names a developer or
 * configuration fault, never a denial.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RefusalReason: string
{
    /** The model does not implement `QueryableResource`. */
    case MODEL_UNDECLARED = 'model_undeclared';

    /** The model implements `AuthorizableResource`, or its morph type is too long to identify a record. */
    case MODEL_CONTRACT = 'model_contract';

    /** The model overrides a method that could change what `check()` sees on load. */
    case MODEL_OVERRIDE = 'model_override';

    /** The model has a `retrieved` listener or observer, which could change a model on load. */
    case MODEL_LISTENER = 'model_listener';

    /** The key or a tenant column has an accessor. */
    case COLUMN_ACCESSOR = 'column_accessor';

    /** The key or a tenant column has a cast other than the key's own kind. */
    case COLUMN_CAST = 'column_cast';

    /** The key or a tenant column is missing or of a type the scope cannot compare exactly. */
    case COLUMN_TYPE = 'column_type';

    /** The connection, or the database, does not use UTF-8. */
    case CONNECTION_CHARSET = 'connection_charset';

    /** The model's connection is not SQLite, PostgreSQL or MySQL. */
    case DRIVER = 'driver';

    /** The bound resource tenant resolver is not the package's declared resolver. */
    case TENANT_RESOLVER = 'tenant_resolver';

    /** A statement reads a namespace, or an authentication requirement, through a seam not marked `ScopeInvariant`. */
    case SCOPE_VARIANT_SOURCE = 'scope_variant_source';

    /** The bound tenant tree is not the flat tree, which part 1 alone compiles. */
    case TENANT_TREE = 'tenant_tree';

    /** The subject holds the action platform-wide, which admits rows of other tenants. */
    case PLATFORM_ADMISSION = 'platform_admission';

    /** A policy, guardrail or boundary document cannot be read. */
    case INVALID_POLICY = 'invalid_policy';

    /** A statement that names the action cannot be evaluated. */
    case INVALID_STATEMENT = 'invalid_statement';

    /** A statement that names the action reads the resource namespace. */
    case RESOURCE_NAMESPACE = 'resource_namespace';

    /** A statement that names the action has a resource pattern naming less than the whole type. */
    case RESOURCE_PATTERN = 'resource_pattern';

    /** A policy attached to a record of the type names the action. */
    case RECORD_ATTACHMENT = 'record_attachment';

    /** The query has a union. */
    case QUERY_UNION = 'query_union';

    /** The query selects from something other than the model's table. */
    case QUERY_FROM = 'query_from';

    /** A constraint at the top of the query is joined with `or`, which would bypass the scope. */
    case QUERY_OR = 'query_or';

    /** The scope was removed from the query after `whereAuthorized()`. */
    case SCOPE_REMOVED = 'scope_removed';
}
