<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Settings;

/**
 * Every setting the shipped configuration defines, by its path, with the kind
 * of value it holds, which decides whether the report may show it.
 *
 * Only values of these kinds are shown, and only when the value has the shape
 * its kind expects: class names, table names and their prefix, switches, whole
 * numbers, the names of a guard, a connection, a cache store, a queue or a log
 * channel, permission names and action names. A setting of any other kind,
 * `opaque`, such as the context keys, the session scopes or the cache prefix,
 * is shown by its type alone, as is every setting the package does not define.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SettingCatalogue
{
    /** @var string A class name. */
    public const string CLASS_NAME = 'class';

    /** @var string A list of class names. */
    public const string CLASS_LIST = 'classes';

    /** @var string Names, such as morph types, mapped to class names. */
    public const string CLASS_MAP = 'class_map';

    /** @var string A table's name. */
    public const string TABLE = 'table';

    /** @var string The prefix of the tables' default names, empty or not. */
    public const string TABLE_PREFIX = 'table_prefix';

    /** @var string A switch, true or false. */
    public const string SWITCH = 'boolean';

    /** @var string A whole number. */
    public const string WHOLE_NUMBER = 'integer';

    /** @var string The name of a guard, a connection, a cache store, a queue or a log channel, or null. */
    public const string NAME = 'name';

    /** @var string A list of names, such as action names. */
    public const string NAME_LIST = 'names';

    /** @var string Application names mapped to permission names. */
    public const string NAME_MAP = 'name_map';

    /** @var string A value never shown. */
    public const string OPAQUE = 'opaque';

    /** @var list<string> The kinds that map names to values, shown as a map even when empty. */
    public const array MAPS = [self::CLASS_MAP, self::NAME_MAP];

    /** @var array<string, string> Each setting's path mapped to the kind of value it holds, in the order the shipped configuration lists them. */
    public const array SETTINGS = [
        'authorization.models.role'                                  => self::CLASS_NAME,
        'authorization.models.permission'                            => self::CLASS_NAME,
        'authorization.models.policy'                                => self::CLASS_NAME,
        'authorization.connection'                                   => self::NAME,
        'authorization.tables.prefix'                                => self::TABLE_PREFIX,
        'authorization.tables.roles'                                 => self::TABLE,
        'authorization.tables.permissions'                           => self::TABLE,
        'authorization.tables.policies'                              => self::TABLE,
        'authorization.tables.role_permissions'                      => self::TABLE,
        'authorization.tables.authorizable_roles'                    => self::TABLE,
        'authorization.tables.authorizable_permissions'              => self::TABLE,
        'authorization.tables.authorizable_policies'                 => self::TABLE,
        'authorization.tables.resource_policies'                     => self::TABLE,
        'authorization.tables.authorizable_boundaries'               => self::TABLE,
        'authorization.tables.guardrails'                            => self::TABLE,
        'authorization.tables.grant_usage'                           => self::TABLE,
        'authorization.tables.usage_coverage'                        => self::TABLE,
        'authorization.defaults.guard'                               => self::NAME,
        'authorization.permission_enums'                             => self::CLASS_LIST,
        'authorization.permission_providers'                         => self::CLASS_LIST,
        'authorization.gate.enabled'                                 => self::SWITCH,
        'authorization.log_channel'                                  => self::NAME,
        'authorization.policy_store'                                 => self::CLASS_NAME,
        'authorization.policies.limits.document_bytes'               => self::WHOLE_NUMBER,
        'authorization.policies.limits.statements'                   => self::WHOLE_NUMBER,
        'authorization.policies.limits.conditions'                   => self::WHOLE_NUMBER,
        'authorization.policies.limits.pattern_length'               => self::WHOLE_NUMBER,
        'authorization.query_scoping.max_anchors'                    => self::WHOLE_NUMBER,
        'authorization.query_scoping.max_scopes'                     => self::WHOLE_NUMBER,
        'authorization.query_scoping.max_attachments'                => self::WHOLE_NUMBER,
        'authorization.bulk.chunk_size'                              => self::WHOLE_NUMBER,
        'authorization.context.keys'                                 => self::OPAQUE,
        'authorization.context.sources'                              => self::CLASS_LIST,
        'authorization.attributes.resources'                         => self::CLASS_MAP,
        'authorization.attributes.subjects'                          => self::CLASS_MAP,
        'authorization.subject_resolver'                             => self::CLASS_NAME,
        'authorization.tenant_tree'                                  => self::CLASS_NAME,
        'authorization.identity_directory'                           => self::CLASS_NAME,
        'authorization.application_access'                           => self::NAME_MAP,
        'authorization.resource_tenant_resolver'                     => self::CLASS_NAME,
        'authorization.requirement_checker'                          => self::CLASS_NAME,
        'authorization.session.source'                               => self::CLASS_NAME,
        'authorization.session.scopes'                               => self::OPAQUE,
        'authorization.cache.store'                                  => self::NAME,
        'authorization.cache.ttl'                                    => self::WHOLE_NUMBER,
        'authorization.cache.prefix'                                 => self::OPAQUE,
        'authorization.hierarchy.enabled'                            => self::SWITCH,
        'authorization.rank.enabled'                                 => self::SWITCH,
        'authorization.administration.max_impact'                    => self::WHOLE_NUMBER,
        'authorization.administration.retries'                       => self::WHOLE_NUMBER,
        'authorization.reviews.limit'                                => self::WHOLE_NUMBER,
        'authorization.usage.enabled'                                => self::SWITCH,
        'authorization.usage.interval'                               => self::WHOLE_NUMBER,
        'authorization.usage.batch'                                  => self::WHOLE_NUMBER,
        'authorization.usage.connection'                             => self::NAME,
        'authorization.usage.queue'                                  => self::NAME,
        'authorization.usage.retention'                              => self::WHOLE_NUMBER,
        'authorization.events.decisions.denials'                     => self::SWITCH,
        'authorization.events.decisions.insufficient_authentication' => self::SWITCH,
        'authorization.events.decisions.previews'                    => self::SWITCH,
        'authorization.events.decisions.allows'                      => self::NAME,
        'authorization.events.decisions.sensitive_actions'           => self::NAME_LIST,
        'authorization.grant_hooks'                                  => self::CLASS_LIST,
    ];

    /**
     * Return the kind of value the setting under the path holds, `opaque` for
     * one the package does not define.
     *
     * @param  string  $path
     * @return string
     */
    public static function kindOf(string $path): string
    {
        return self::SETTINGS[$path] ?? self::OPAQUE;
    }
}
