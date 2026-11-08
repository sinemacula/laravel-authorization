<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query\Enums;

/**
 * Why an authorized scope, `whereAuthorized()` or the model-level
 * `AuthorizedScope`, refused to scope a query (AUTHZ-10.2, N64): the scope
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

    /** The key or a tenant column compares other than byte for byte, under a collation that is not exact. */
    case COLUMN_COLLATION = 'column_collation';

    /** The bound tenant tree's subtree query runs on another connection than the model's. */
    case SUBTREE_CONNECTION = 'subtree_connection';

    /** The policies attached to records are kept on another connection than the model's. */
    case ATTACHMENT_CONNECTION = 'attachment_connection';

    /** The column holding an attached record's key has a collation the key's text cannot be compared under: one not byte for byte on SQLite or PostgreSQL, or not utf8mb4 on MySQL. */
    case ATTACHMENT_COLLATION = 'attachment_collation';

    /** A value the condition must inline, a tenant's, an application's, a policy's or one the tenant tree's subtree query is bound to, cannot be written as the database reads it bound, or that query's text holds a question mark that is not a placeholder. */
    case INLINE_VALUE = 'inline_value';

    /** The condition reads the authorization tables, which `check()` reads on the write connection, in a query that is not itself run (nested in another, or compiled to text), so cannot be put on the write connection, on a connection with a separate read connection, outside a transaction. */
    case READ_REPLICA = 'read_replica';

    /** The tenants the subject's grants and the type's policies are kept in, or the classes of rows they make, are more than `authorization.query_scoping` allows. */
    case TOO_MANY_SCOPES = 'too_many_scopes';

    /** The policies attached to records of the type in one scope are more than `authorization.query_scoping.max_attachments` allows. */
    case TOO_MANY_ATTACHMENTS = 'too_many_attachments';

    /** A policy, guardrail or boundary document cannot be read. */
    case INVALID_POLICY = 'invalid_policy';

    /** A statement that names the action cannot be evaluated. */
    case INVALID_STATEMENT = 'invalid_statement';

    /** A statement that names the action reads the resource namespace. */
    case RESOURCE_NAMESPACE = 'resource_namespace';

    /** A statement that names the action has a resource pattern the scope cannot compare with a key, or an integer id outside 64 bits. */
    case RESOURCE_PATTERN = 'resource_pattern';

    /** The query has a union. */
    case QUERY_UNION = 'query_union';

    /** The query selects from something other than the model's table. */
    case QUERY_FROM = 'query_from';

    /** A constraint at the top of the query is joined with `or` after the scope's condition, which would bypass it. */
    case QUERY_OR = 'query_or';

    /** A constraint was added at the top of the query after its scope was applied or last guarded, outside the group that holds the others. */
    case QUERY_CHANGED = 'query_changed';

    /** The scope was removed after `whereAuthorized()`, or never applied: called inside a `where` group or a relation's definition, or run past its scopes. */
    case SCOPE_REMOVED = 'scope_removed';

    /** A model-level scope was applied while a scope was being decided: it is on the subject's model, or on a model the decision reads. */
    case REENTRANT = 'reentrant';

    /** A query scoped through a preview is run as a write, an update, a delete or an insert from it, which a preview never makes. */
    case PREVIEW_WRITE = 'preview_write';
}
