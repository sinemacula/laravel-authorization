<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Evaluation\PolicyValidator;

/**
 * The context keys declared to the package: its own, those given at
 * construction (the `authorization.context.keys` configuration) and those an
 * application or sibling package registers from a service provider.
 *
 * The catalogue lives in the container, one per application, and holds no
 * static state: what one registers is seen by every policy written after it. A
 * key is a full dot path of at least two segments, the namespace first, each in
 * the condition key syntax, of at most `PolicyValidator::KEY_LENGTH`
 * characters.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DeclaredContextKeyCatalogue implements ContextKeyCatalogue
{
    /** @var array<string, string> The keys the package declares, by dot path, with their types. */
    public const array PACKAGE_KEYS = [
        'authentication.guard'     => 'string',
        'authentication.user_id'   => 'string',
        'authentication.user_type' => 'string',
        'environment.time'         => 'time',
        'request.ip'               => 'ip',
        'request.method'           => 'string',
        'request.route'            => 'string',
    ];

    /** @var array<string, \SineMacula\Laravel\Authorization\Context\ContextKey> Every declared key, by dot path. */
    private array $keys = [];

    /**
     * Create a new declared context key catalogue with the package's keys and
     * the given ones.
     *
     * @param  array<string, array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>>  $keys
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(array $keys = [])
    {
        foreach (self::PACKAGE_KEYS as $path => $type) {
            $this->declare($path, ContextKeyType::from($type));
        }

        foreach ($keys as $namespace => $namespaceKeys) {
            $this->register($namespace, $namespaceKeys);
        }
    }

    /**
     * Declare one key by its full dot path.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\Authorization\Enums\ContextKeyType  $type
     * @param  bool  $isTestable
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function declare(string $path, ContextKeyType $type, bool $isTestable = true): void
    {
        if (!self::isValidPath($path)) {
            $syntax = 'a namespace and one or more \'.\'-separated segments of letters, digits, \'_\' and \'-\'';

            throw new \InvalidArgumentException("Context key '{$path}' must be {$syntax}, and at most " . PolicyValidator::KEY_LENGTH . ' characters.');
        }

        $declared = $this->keys[$path] ?? null;

        if ($declared !== null && ($declared->type !== $type || $declared->isTestable !== $isTestable)) {
            throw new \InvalidArgumentException("Context key '{$path}' is already declared as {$declared->type->value}" . ($declared->isTestable ? '' : ', untestable') . '.');
        }

        $this->keys[$path] = $declared ?? new ContextKey($path, $type, $isTestable);
    }

    /**
     * Register a namespace's keys, each a dot path within the namespace mapped
     * to its type.
     *
     * @param  string  $namespace
     * @param  array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>  $keys
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function register(string $namespace, array $keys): void
    {
        foreach ($keys as $path => $type) {
            $this->declare("{$namespace}.{$path}", self::typeOf("{$namespace}.{$path}", $type));
        }
    }

    /**
     * Determine whether a policy may read the key at the dot path, tested with
     * the operator when one is given.
     *
     * @param  string  $path
     * @param  string|null  $operator
     * @return bool
     */
    #[\Override]
    public function permits(string $path, ?string $operator = null): bool
    {
        $key = $this->keys[$path] ?? null;

        return $key !== null && ($operator === null || ($key->isTestable && $key->type->suits($operator)));
    }

    /**
     * Return the declared key at the dot path, or null when none is declared.
     *
     * @param  string  $path
     * @return \SineMacula\Laravel\Authorization\Context\ContextKey|null
     */
    #[\Override]
    public function find(string $path): ?ContextKey
    {
        return $this->keys[$path] ?? null;
    }

    /**
     * Return every declared key, by its dot path, in order of path.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Context\ContextKey>
     */
    #[\Override]
    public function keys(): array
    {
        $keys = $this->keys;

        \ksort($keys, \SORT_STRING);

        return $keys;
    }

    /**
     * Return every namespace a declared key belongs to, in order of name.
     *
     * @return list<string>
     */
    #[\Override]
    public function namespaces(): array
    {
        $namespaces = \array_values(\array_unique(\array_map(static fn (ContextKey $key): string => $key->namespace(), $this->keys)));

        \sort($namespaces, \SORT_STRING);

        return $namespaces;
    }

    /**
     * Return the type a key is registered with, refusing a name that is not a
     * type.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string  $type
     * @return \SineMacula\Laravel\Authorization\Enums\ContextKeyType
     *
     * @throws \InvalidArgumentException
     */
    private static function typeOf(string $path, ContextKeyType|string $type): ContextKeyType
    {
        if ($type instanceof ContextKeyType) {
            return $type;
        }

        $types = \implode(', ', \array_column(ContextKeyType::cases(), 'value'));

        return ContextKeyType::tryFrom($type) ?? throw new \InvalidArgumentException("Context key '{$path}' has an unknown type '{$type}'; use one of {$types}.");
    }

    /**
     * Determine whether the path is a namespace and at least one more segment,
     * in the condition key syntax and not too long.
     *
     * @param  string  $path
     * @return bool
     */
    private static function isValidPath(string $path): bool
    {
        return \str_contains($path, '.')
            && \strlen($path) <= PolicyValidator::KEY_LENGTH
            && \preg_match(PolicyValidator::KEY_PATTERN, $path) === 1;
    }
}
