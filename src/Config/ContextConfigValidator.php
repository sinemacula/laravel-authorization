<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ContextSource;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Boot-time validator for the `authorization.context` config (N25, N26), run by
 * `ConfigValidator`.
 *
 * `context.keys` must map each namespace to its keys, each a dot path within
 * the namespace mapped to the name of a type, which the context key catalogue
 * accepts: a valid path, a known type, and no key declared again with another
 * type. `context.sources` must list classes implementing `ContextSource`, each
 * resolved from the container to read its namespace, which must be a name, not
 * reserved and claimed by no other source.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ContextConfigValidator
{
    /** @var string The config key of the context keys. */
    private const string KEYS = 'authorization.context.keys';

    /** @var string The config key of the context sources. */
    private const string SOURCES = 'authorization.context.sources';

    /**
     * Validate the supplied `context` config, throwing on the first failure.
     *
     * @param  mixed  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config, Container $container): void
    {
        if (!\is_array($config)) {
            throw new InvalidAuthorizationConfigException('authorization.context', 'expected an array with keys and sources, got ' . \get_debug_type($config) . '.');
        }

        self::validateKeys($config['keys'] ?? []);
        self::validateSources($config['sources'] ?? [], $container);
    }

    /**
     * Validate that `context.keys` maps namespaces to their keys' types, and
     * that the context key catalogue accepts every key.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateKeys(mixed $value): void
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException(self::KEYS, 'expected an array of namespaces to their keys, got ' . \get_debug_type($value) . '.');
        }

        foreach ($value as $namespace => $keys) {
            if (!\is_string($namespace) || !self::isTypeMap($keys)) {
                $reason = 'each namespace must map key paths to the names of their types, such as [\'tenant\' => [\'plan\' => \'string\']].';

                throw new InvalidAuthorizationConfigException(self::KEYS, $reason);
            }
        }

        /** @var array<string, array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>> $keys */
        $keys = $value;

        try {
            new DeclaredContextKeyCatalogue($keys);
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidAuthorizationConfigException(self::KEYS, $exception->getMessage());
        }
    }

    /**
     * Validate that every entry of `context.sources` is a class implementing
     * `ContextSource`, and that the namespaces they supply are names, not
     * reserved and supplied once.
     *
     * @param  mixed  $value
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateSources(mixed $value, Container $container): void
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException(self::SOURCES, 'expected an array of class names, got ' . \get_debug_type($value) . '.');
        }

        $claimed = [];

        foreach ($value as $index => $class) {
            $namespace = self::namespaceOf("{$index}", $class, $container);

            if (\preg_match(CheckContextFactory::NAMESPACE_PATTERN, $namespace) !== 1 || \in_array($namespace, ContextSource::RESERVED_NAMESPACES, true)) {
                $reason = "source '{$class}' supplies the namespace '{$namespace}', which is not a name or is reserved ("
                    . \implode(', ', ContextSource::RESERVED_NAMESPACES) . ').';

                throw new InvalidAuthorizationConfigException(self::SOURCES . ".{$index}", $reason);
            }

            if (isset($claimed[$namespace])) {
                $reason = "source '{$class}' supplies the namespace '{$namespace}', which '{$claimed[$namespace]}' supplies too.";

                throw new InvalidAuthorizationConfigException(self::SOURCES . ".{$index}", $reason);
            }

            $claimed[$namespace] = $class;
        }
    }

    /**
     * Return the namespace the source an entry names supplies, refusing an
     * entry that is not a class implementing `ContextSource`.
     *
     * @param  string  $index
     * @param  mixed  $class
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     *
     * @phpstan-assert class-string<\SineMacula\Laravel\Authorization\Contracts\ContextSource> $class
     */
    private static function namespaceOf(string $index, mixed $class, Container $container): string
    {
        if (!\is_string($class) || $class === '') {
            throw new InvalidAuthorizationConfigException(self::SOURCES . ".{$index}", 'entry must be a non-empty class-string, got ' . \get_debug_type($class) . '.');
        }

        if (!\class_exists($class)) {
            throw new InvalidAuthorizationConfigException(self::SOURCES . ".{$index}", "class '{$class}' does not exist.");
        }

        if (!\is_subclass_of($class, ContextSource::class)) {
            throw new InvalidAuthorizationConfigException(self::SOURCES . ".{$index}", "class '{$class}' does not implement " . ContextSource::class . '.');
        }

        /** @var \SineMacula\Laravel\Authorization\Contracts\ContextSource $source */
        $source = $container->make($class);

        return $source->namespace();
    }

    /**
     * Determine whether the value maps key paths to types or the names of
     * types.
     *
     * @param  mixed  $keys
     * @return bool
     */
    private static function isTypeMap(mixed $keys): bool
    {
        return \is_array($keys) && \array_filter(
            $keys,
            static fn (mixed $type, int|string $path): bool => !\is_string($path) || !(\is_string($type) || $type instanceof ContextKeyType),
            \ARRAY_FILTER_USE_BOTH,
        ) === [];
    }
}
