<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;

/**
 * Boot-time validator for the `authorization.session` config (AUTHZ-7.5,
 * AUTHZ-13.3), run by `ConfigValidator`.
 *
 * `session.source` must name a class implementing `SessionPolicySource`; null
 * is refused rather than read as "no cap", so a missing source fails at boot
 * instead of changing what caps a check.
 *
 * `session.scopes` maps each scope a credential may carry to a list of action
 * patterns, or lists a scope on its own to name itself. Each scope must be a
 * non-empty string named once, each list must hold one pattern or more, each a
 * non-empty string, and every pattern, a scope listed on its own included, must
 * cover at least one permission the package or the application declares, as a
 * policy's action patterns must: the bound `ActionCatalogue` is resolved for
 * it, so the declared permissions are read at boot, and only when the map names
 * a scope.
 *
 * The block sets no key but `source` and `scopes` (N116); `scopes` is empty
 * when left out, and refused when set to null.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionConfigValidator
{
    /** @var list<string> The settings the block may set. */
    public const array SETTINGS = ['source', 'scopes'];

    /** @var string The config key of the session policy source. */
    public const string SOURCE = 'authorization.session.source';

    /** @var string The config key of the scope map. */
    public const string SCOPES = 'authorization.session.scopes';

    /**
     * Validate the supplied `session` config, throwing on the first failure.
     *
     * @param  mixed  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config, Container $container): void
    {
        $block = ConfigBlock::of('authorization.session', $config, self::SETTINGS);

        self::validateSource(ConfigBlock::entry($block, 'source', NoSessionPolicy::class));
        self::validateCoverage(self::scopeMap(ConfigBlock::entry($block, 'scopes', [])), $container);
    }

    /**
     * Return the scope map `session.scopes` holds, each scope keyed to the
     * patterns it names, a scope listed on its own naming itself, refusing a
     * value that does not map each scope, once, to a non-empty list of patterns
     * or list it on its own.
     *
     * The scope map is built through here at run time too, so an entry changed
     * after boot is refused there, never skipped. Whether each pattern covers a
     * declared permission is checked at boot only.
     *
     * @param  mixed  $value
     * @return array<string, list<non-empty-string>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function scopeMap(mixed $value): array
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException(self::SCOPES, 'expected an array of scopes to their action patterns, got ' . \get_debug_type($value) . '.');
        }

        $patterns = [];

        foreach ($value as $key => $entry) {
            [$scope, $list] = \is_int($key) ? [$entry, [$entry]] : [$key, $entry];

            if (!\is_string($scope) || $scope === '' || !self::isPatternList($list)) {
                $reason = 'each scope must be a non-empty string, listed on its own or mapped to a non-empty list of action patterns, such as'
                    . ' [\'posts.read\', \'editor\' => [\'posts:*\']].';

                throw new InvalidAuthorizationConfigException(self::SCOPES, $reason);
            }

            if (\array_key_exists($scope, $patterns)) {
                throw new InvalidAuthorizationConfigException(self::SCOPES, "the scope '{$scope}' is named more than once.");
            }

            $patterns[$scope] = $list;
        }

        return $patterns;
    }

    /**
     * Validate that `session.source` names a class implementing the contract.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateSource(mixed $value): void
    {
        $reason = match (true) {
            $value                        === null           => 'a session policy source class is required; set it to \\' . NoSessionPolicy::class . ' for no credential cap.',
            !\is_string($value) || $value === ''             => 'expected a class-string, got ' . \get_debug_type($value) . '.',
            !\class_exists($value)                           => "class '{$value}' does not exist.",
            !\is_a($value, SessionPolicySource::class, true) => "class '{$value}' does not implement " . SessionPolicySource::class . '.',
            default                                          => null,
        };

        if ($reason !== null) {
            throw new InvalidAuthorizationConfigException(self::SOURCE, $reason);
        }
    }

    /**
     * Validate that every pattern of every scope covers at least one permission
     * the package or the application declares, reading the action catalogue
     * only when there is a pattern to check.
     *
     * @param  array<array-key, list<string>>  $patterns
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateCoverage(array $patterns, Container $container): void
    {
        if ($patterns === []) {
            return;
        }

        /** @var \SineMacula\Laravel\Authorization\Contracts\ActionCatalogue $catalogue */
        $catalogue = $container->make(ActionCatalogue::class);

        foreach ($patterns as $scope => $list) {
            foreach ($list as $pattern) {
                if (!PackagePermissions::covers($pattern) && !$catalogue->covers($pattern)) {
                    throw new InvalidAuthorizationConfigException(self::SCOPES, "the scope '{$scope}' names '{$pattern}', which covers no declared permission.");
                }
            }
        }
    }

    /**
     * Determine whether the value is a non-empty list of non-empty strings.
     *
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true list<non-empty-string> $value
     */
    private static function isPatternList(mixed $value): bool
    {
        if (!\is_array($value) || $value === [] || !\array_is_list($value)) {
            return false;
        }

        foreach ($value as $pattern) {
            if (!\is_string($pattern) || $pattern === '') {
                return false;
            }
        }

        return true;
    }
}
