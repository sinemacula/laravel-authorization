<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

/**
 * What a subject's credential says about its scopes, as a subject resolver read
 * it (N126): either the credential carries no cap (`uncapped()`), or it carries
 * the scopes given (`of()`), each a string that is not empty, where an empty
 * list carries none granted and allows nothing. A `Subject` that carries none
 * of these says nothing about its credential's scopes, which is not the same as
 * carrying no cap: the session policy source then establishes them itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CredentialScopes
{
    /**
     * Create the scopes of a credential.
     *
     * @param  list<string>|null  $scopes
     */
    private function __construct(

        /** The scopes the credential carries, or null when it carries no cap. */
        private ?array $scopes,
    ) {}

    /**
     * Return the scopes of a credential that carries no cap.
     *
     * @return self
     */
    public static function uncapped(): self
    {
        return new self(null);
    }

    /**
     * Return the scopes of a credential that carries those given, refusing any
     * that are not a list of strings that are not empty; an empty list carries
     * none granted, and allows nothing.
     *
     * @param  list<string>  $scopes
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(array $scopes): self
    {
        if (!self::isScopeList($scopes)) {
            throw new \InvalidArgumentException('The scopes of a credential must be a list of strings that are not empty.');
        }

        return new self($scopes);
    }

    /**
     * Determine whether the credential carries a cap, an empty one included.
     *
     * @return bool
     */
    public function isCapped(): bool
    {
        return $this->scopes !== null;
    }

    /**
     * Return the scopes the credential carries, or null when it carries no cap.
     *
     * @return list<string>|null
     */
    public function scopes(): ?array
    {
        return $this->scopes;
    }

    /**
     * Determine whether the scopes are a list of strings that are not empty.
     *
     * @param  array<mixed>  $scopes
     * @return bool
     */
    private static function isScopeList(array $scopes): bool
    {
        $named = \array_filter($scopes, static fn (mixed $scope): bool => \is_string($scope) && $scope !== '');

        return \array_is_list($scopes) && \count($named) === \count($scopes);
    }
}
