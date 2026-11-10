<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Config\SessionConfigValidator;

/**
 * The scope map (`authorization.session.scopes`): what each scope a credential
 * may carry names, as action patterns (AUTHZ-7.5).
 *
 * A scope mapped to a list of patterns names those patterns; a scope listed on
 * its own, by a numeric key, names itself, as does every scope the map does not
 * name: by default a scope is an action or an action pattern. The map is
 * validated when the application boots (see `SessionConfigValidator`), and its
 * shape again when it is built here, so an entry of any other shape changed
 * after boot is refused with `InvalidAuthorizationConfigException`, never
 * skipped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionScopes
{
    /**
     * Create a new scope map.
     *
     * @param  array<string, list<string>>  $map
     */
    public function __construct(

        /** Each scope the map names, with the patterns it names. */
        private array $map = [],
    ) {}

    /**
     * Build the scope map from its configuration: each scope keyed to a list of
     * patterns, or listed on its own to name itself, refusing any other shape.
     *
     * @param  mixed  $value
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function fromConfig(mixed $value): self
    {
        return new self(SessionConfigValidator::scopeMap($value));
    }

    /**
     * Return the action patterns the scopes name, in the order the scopes are
     * given, each pattern once.
     *
     * @param  list<string>  $scopes
     * @return list<string>
     */
    public function patternsFor(array $scopes): array
    {
        $patterns = [];

        foreach ($scopes as $scope) {
            foreach ($this->map[$scope] ?? [$scope] as $pattern) {
                $patterns[$pattern] = $pattern;
            }
        }

        return \array_values($patterns);
    }

    /**
     * Determine whether the map names the scope.
     *
     * @param  string  $scope
     * @return bool
     */
    public function isMapped(string $scope): bool
    {
        return \array_key_exists($scope, $this->map);
    }

    /**
     * Return the name of every scope the map names, in the order it names them.
     *
     * @return list<string>
     */
    public function names(): array
    {
        return \array_map(\strval(...), \array_keys($this->map));
    }
}
