<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Boot-time validator for the `authorization.tables` config, run by
 * `ConfigValidator`.
 *
 * The block must be an array setting no key but the package's twelve tables
 * (N116). Each name it sets must be a plain SQL identifier: a letter or an
 * underscore, then letters, digits and underscores. A name qualified by a
 * schema (`schema.table`) is refused, as the migrations build the names of
 * their indexes and keys from the table's name, and a dot there would break
 * them. A name the block leaves out is the key's own, as the config file has
 * it; a name set to null is refused. The twelve names, those left out included,
 * must be distinct, compared whatever their case, since some databases fold it.
 *
 * Each name is bounded by its own length (`LENGTHS`): the migrations name each
 * index, unique index, primary key and foreign key of a table after the table,
 * and the longest such name must fit in 63 characters. MySQL refuses a name
 * over 64; PostgreSQL cuts one over 63 short without a word, after which a
 * migration that looks an index up by its full name no longer finds it. The
 * bound is the limit less the longest suffix a migration adds to the table's
 * name:
 *
 * - `roles`, `permissions`: `_name_guard_owner_unique`, 24;
 * - `policies`: `_name_inline_unique`, 19;
 * - `role_permissions`: `_role_id_permission_id_primary`, Laravel's name for
 *   its primary key, 30;
 * - `authorizable_roles`, `authorizable_policies`: `_review_order_index`, 19;
 * - `authorizable_permissions`: `_permission_id_foreign`, Laravel's name for
 *   its foreign key, 22;
 * - `resource_policies`, `authorizable_boundaries`, `guardrails`:
 *   `_policy_id_foreign`, 18;
 * - `grant_usage`: `_grant_key_primary`, 18;
 * - `usage_coverage`: `_until_index`, 12.
 *
 * Laravel puts the connection's table prefix before the names it builds, so the
 * bounds hold for a connection without one; a prefix shortens what is left for
 * the table's name by its own length.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TableConfigValidator
{
    /** @var string The config key of the block. */
    public const string KEY = 'authorization.tables';

    /** @var int The most characters an identifier may have in every database supported: PostgreSQL's 63, within MySQL's 64. */
    public const int IDENTIFIER_LENGTH = 63;

    /** @var array<string, int> The most characters each table's name may have, so every name a migration builds from it fits. */
    public const array LENGTHS = [
        'roles'                    => self::IDENTIFIER_LENGTH - 24,
        'permissions'              => self::IDENTIFIER_LENGTH - 24,
        'policies'                 => self::IDENTIFIER_LENGTH - 19,
        'role_permissions'         => self::IDENTIFIER_LENGTH - 30,
        'authorizable_roles'       => self::IDENTIFIER_LENGTH - 19,
        'authorizable_permissions' => self::IDENTIFIER_LENGTH - 22,
        'authorizable_policies'    => self::IDENTIFIER_LENGTH - 19,
        'resource_policies'        => self::IDENTIFIER_LENGTH - 18,
        'authorizable_boundaries'  => self::IDENTIFIER_LENGTH - 18,
        'guardrails'               => self::IDENTIFIER_LENGTH - 18,
        'grant_usage'              => self::IDENTIFIER_LENGTH - 18,
        'usage_coverage'           => self::IDENTIFIER_LENGTH - 12,
    ];

    /** @var string A plain SQL identifier. */
    private const string IDENTIFIER = '/\A[A-Za-z_][A-Za-z0-9_]*\z/';

    /** @var string What a plain SQL identifier is, for a message. */
    private const string IDENTIFIER_SHAPE = 'a letter or an underscore, then letters, digits and underscores, with no schema.';

    /**
     * Validate the supplied `tables` config, throwing on the first failure.
     *
     * @param  mixed  $config
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config): void
    {
        $block = ConfigBlock::of(self::KEY, $config, \array_keys(self::LENGTHS));
        $named = [];

        foreach (\array_keys(self::LENGTHS) as $key) {
            $named = self::distinct($key, self::name($key, ConfigBlock::entry($block, $key, $key)), $named);
        }
    }

    /**
     * Return the names given, the table's added under its key, refusing a name
     * another table already has, whatever its case.
     *
     * @param  string  $key
     * @param  string  $name
     * @param  array<string, string>  $named
     * @return array<string, string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function distinct(string $key, string $name, array $named): array
    {
        $folded = \strtolower($name);

        if (isset($named[$folded])) {
            $reason = "table '{$name}' is already the name of " . self::KEY . ".{$named[$folded]}.";

            throw new InvalidAuthorizationConfigException(self::KEY . ".{$key}", $reason, IssueCode::DUPLICATE, 'a name no other table has', 'string');
        }

        $named[$folded] = $key;

        return $named;
    }

    /**
     * Return the name of the table under the key, refusing one that is not a
     * plain identifier of at most the length the key allows.
     *
     * @param  string  $key
     * @param  mixed  $name
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function name(string $key, mixed $name): string
    {
        $length   = self::LENGTHS[$key] ?? ConfigBlock::refuseUnknownKey(self::KEY, $key, \array_keys(self::LENGTHS));
        $expected = "a plain identifier of at most {$length} characters";

        if (!\is_string($name) || $name === '') {
            $reason = 'expected a table name, got ' . ConfigValidator::describe($name) . '.';

            throw new InvalidAuthorizationConfigException(self::KEY . ".{$key}", $reason, IssueCode::INVALID_TYPE, $expected, \get_debug_type($name));
        }

        [$issue, $reason] = match (true) {
            \preg_match(self::IDENTIFIER, $name) !== 1 => [IssueCode::INVALID_VALUE, "table '{$name}' is not a plain identifier: " . self::IDENTIFIER_SHAPE],
            \strlen($name) > $length                   => [
                IssueCode::OUT_OF_RANGE,
                "table '{$name}' is longer than {$length} characters, which leaves no room for the names of its indexes and keys.",
            ],
            default => [null, ''],
        };

        return $issue === null ? $name : throw new InvalidAuthorizationConfigException(self::KEY . ".{$key}", $reason, $issue, $expected, 'string');
    }
}
