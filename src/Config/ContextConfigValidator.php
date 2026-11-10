<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Context\AssuranceKeys;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
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
 * The bound `AuthenticationContext` is resolved too, to read the namespaces it
 * contributes beside `authentication`: each must be a name, not reserved and
 * listed once, and no source may claim one, so a clash is refused at boot
 * rather than on the first check. The assurance keys it declares must each be a
 * name with no `.`, or a name followed by one trailing `*`, or boot fails
 * closed (N104).
 *
 * The block sets no key but `keys` and `sources` (N116); each is an empty list
 * when left out, and refused when set to null.
 *
 * It runs at boot, after every service provider has registered, so the
 * authentication context read is the one bound last, whichever provider bound
 * it (N104).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ContextConfigValidator
{
    /** @var list<string> The settings the block may set. */
    public const array SETTINGS = ['keys', 'sources'];

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
        $block = ConfigBlock::of('authorization.context', $config, self::SETTINGS);

        self::validateKeys(ConfigBlock::entry($block, 'keys', []));
        self::validateSources(ConfigBlock::entry($block, 'sources', []), $container);
    }

    /**
     * Return the namespaces `context.keys` declares, each mapped to its keys'
     * types, refusing a value of any other shape.
     *
     * The context key catalogue is built through here at run time too, so a
     * value changed after boot is refused there, never cast; the catalogue
     * itself refuses a key it does not accept.
     *
     * @param  mixed  $value
     * @return array<string, array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function keyMap(mixed $value): array
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

        /** @var array<string, array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>> */
        return $value;
    }

    /**
     * Return the classes `context.sources` lists, refusing a value that is not
     * an array and an entry that is not a class implementing `ContextSource`.
     *
     * The check context factory reads the list through here at run time, before
     * it resolves any source, so an entry changed after boot is refused there
     * too, never cast.
     *
     * @param  mixed  $value
     * @return array<array-key, class-string<\SineMacula\Laravel\Authorization\Contracts\ContextSource>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function sources(mixed $value): array
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException(self::SOURCES, 'expected an array of class names, got ' . \get_debug_type($value) . '.');
        }

        foreach ($value as $index => $class) {
            self::sourceClass("{$index}", $class);
        }

        /** @var array<array-key, class-string<\SineMacula\Laravel\Authorization\Contracts\ContextSource>> */
        return $value;
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
        $keys = self::keyMap($value);

        try {
            new DeclaredContextKeyCatalogue($keys);
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidAuthorizationConfigException(self::KEYS, $exception->getMessage());
        }
    }

    /**
     * Validate that every entry of `context.sources` is a class implementing
     * `ContextSource`, and that the namespaces they and the authentication
     * context supply are names, not reserved and supplied once.
     *
     * @param  mixed  $value
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateSources(mixed $value, Container $container): void
    {
        $sources = self::sources($value);
        $claimed = self::contributedNamespaces($container);

        foreach ($sources as $index => $class) {
            /** @var \SineMacula\Laravel\Authorization\Contracts\ContextSource $source */
            $source    = $container->make($class);
            $namespace = $source->namespace();

            if (!self::isClaimable($namespace)) {
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
     * Return each namespace the bound authentication context contributes beside
     * `authentication`, mapped to the context's class, refusing one that is not
     * a name, is reserved or is listed twice, and refusing a malformed
     * declaration of its assurance keys. A container with no authentication
     * context bound, as in library-mode embedding, contributes none.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return array<string, string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function contributedNamespaces(Container $container): array
    {
        if (!$container->bound(AuthenticationContext::class)) {
            return [];
        }

        /** @var \SineMacula\Laravel\Authorization\Contracts\AuthenticationContext $authentication */
        $authentication = $container->make(AuthenticationContext::class);
        $claimed        = [];

        try {
            AssuranceKeys::of($authentication);
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidAuthorizationConfigException('authorization.context', $exception->getMessage());
        }

        foreach (\array_diff($authentication->namespaces(), ['authentication']) as $namespace) {
            if (!self::isClaimable($namespace) || isset($claimed[$namespace])) {
                $reason = 'authentication context \'' . $authentication::class . "' contributes the namespace '{$namespace}', which is not a name, is reserved ("
                    . \implode(', ', ContextSource::RESERVED_NAMESPACES) . ') or is listed twice.';

                throw new InvalidAuthorizationConfigException('authorization.context', $reason);
            }

            $claimed[$namespace] = $authentication::class;
        }

        return $claimed;
    }

    /**
     * Determine whether the namespace may be claimed: it is a name and is not
     * reserved.
     *
     * @param  string  $namespace
     * @return bool
     */
    private static function isClaimable(string $namespace): bool
    {
        return \preg_match(CheckContextFactory::NAMESPACE_PATTERN, $namespace) === 1 && !\in_array($namespace, ContextSource::RESERVED_NAMESPACES, true);
    }

    /**
     * Refuse an entry of `context.sources` that is not a class implementing
     * `ContextSource`.
     *
     * @param  string  $index
     * @param  mixed  $class
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     *
     * @phpstan-assert class-string<\SineMacula\Laravel\Authorization\Contracts\ContextSource> $class
     */
    private static function sourceClass(string $index, mixed $class): void
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
