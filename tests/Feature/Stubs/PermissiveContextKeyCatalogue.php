<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Context\ContextKey;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;

/**
 * A context key catalogue for tests that permits every key with every operator,
 * so a test can write a policy reading any context key without declaring it
 * first. Everything else is the wrapped catalogue's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PermissiveContextKeyCatalogue implements ContextKeyCatalogue
{
    /**
     * Create a new permissive context key catalogue.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue  $catalogue
     */
    public function __construct(

        /** The catalogue every declaration and lookup is passed to. */
        private ContextKeyCatalogue $catalogue,
    ) {}

    /**
     * Declare the key on the wrapped catalogue.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\Authorization\Enums\ContextKeyType  $type
     * @param  bool  $isTestable
     * @return void
     */
    #[\Override]
    public function declare(string $path, ContextKeyType $type, bool $isTestable = true): void
    {
        $this->catalogue->declare($path, $type, $isTestable);
    }

    /**
     * Register the namespace's keys on the wrapped catalogue.
     *
     * @param  string  $namespace
     * @param  array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>  $keys
     * @return void
     */
    #[\Override]
    public function register(string $namespace, array $keys): void
    {
        $this->catalogue->register($namespace, $keys);
    }

    /**
     * Permit every key, with every operator.
     *
     * @param  string  $path
     * @param  string|null  $operator
     * @return bool
     */
    #[\Override]
    public function permits(string $path, ?string $operator = null): bool
    {
        return true;
    }

    /**
     * Return the key the wrapped catalogue declares at the dot path.
     *
     * @param  string  $path
     * @return \SineMacula\Laravel\Authorization\Context\ContextKey|null
     */
    #[\Override]
    public function find(string $path): ?ContextKey
    {
        return $this->catalogue->find($path);
    }

    /**
     * Return every key the wrapped catalogue declares.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Context\ContextKey>
     */
    #[\Override]
    public function keys(): array
    {
        return $this->catalogue->keys();
    }

    /**
     * Return every namespace the wrapped catalogue declares a key in.
     *
     * @return list<string>
     */
    #[\Override]
    public function namespaces(): array
    {
        return $this->catalogue->namespaces();
    }
}
