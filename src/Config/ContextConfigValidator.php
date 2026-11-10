<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Context\AssuranceKeys;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ContextSource;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
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
 * The checks of the values' shape (`keys()`, `sources()`) build nothing and can
 * run alone, as the configuration report runs them; the check of the namespaces
 * (`namespaces()`) builds each source and the authentication context, so it
 * runs at boot only.
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

        self::keys(ConfigBlock::entry($block, 'keys', []));
        self::namespaces(self::sources(ConfigBlock::entry($block, 'sources', [])), $container);
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
        /** @var array<string, array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>> */
        return ConfigBlock::entries(self::KEYS, $value, 'an array of namespaces to their keys', self::keyEntry(...));
    }

    /**
     * Validate that one entry of `context.keys` maps a namespace to its keys'
     * paths, each mapped to the name of its type.
     *
     * @param  int|string  $namespace
     * @param  mixed  $keys
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function keyEntry(int|string $namespace, mixed $keys): void
    {
        if (!\is_string($namespace) || !self::isTypeMap($keys)) {
            $reason = 'each namespace must map key paths to the names of their types, such as [\'tenant\' => [\'plan\' => \'string\']].';

            $wanted = 'a namespace mapped to key paths and the names of their types';

            throw new InvalidAuthorizationConfigException(self::KEYS, $reason, IssueCode::INVALID_VALUE, $wanted, \get_debug_type($keys));
        }
    }

    /**
     * Validate that `context.keys` maps namespaces to their keys' types, and
     * that the context key catalogue accepts every key. Nothing is built but
     * the catalogue, from the configuration alone.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function keys(mixed $value): void
    {
        $keys = self::keyMap($value);

        try {
            new DeclaredContextKeyCatalogue($keys);
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidAuthorizationConfigException(self::KEYS, $exception->getMessage(), IssueCode::INVALID_VALUE, 'keys the context key catalogue accepts', 'array');
        }
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
        /** @var array<array-key, class-string<\SineMacula\Laravel\Authorization\Contracts\ContextSource>> */
        return ConfigBlock::entries(self::SOURCES, $value, 'an array of class names', self::source(...));
    }

    /**
     * Validate that the namespaces the sources and the authentication context
     * supply are names, not reserved and supplied once. Each source and the
     * authentication context are built to read them, so this runs at boot only.
     *
     * @param  array<array-key, class-string<\SineMacula\Laravel\Authorization\Contracts\ContextSource>>  $sources
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function namespaces(array $sources, Container $container): void
    {
        $claimed = self::contributedNamespaces($container);

        foreach ($sources as $index => $class) {
            /** @var \SineMacula\Laravel\Authorization\Contracts\ContextSource $source */
            $source    = $container->make($class);
            $namespace = $source->namespace();

            if (!self::isClaimable($namespace)) {
                $reason = "source '{$class}' supplies the namespace '{$namespace}', which is not a name or is reserved ("
                    . \implode(', ', ContextSource::RESERVED_NAMESPACES) . ').';

                $wanted = 'a source supplying a namespace that is a name and not reserved';

                throw new InvalidAuthorizationConfigException(self::SOURCES . ".{$index}", $reason, IssueCode::INVALID_VALUE, $wanted);
            }

            if (isset($claimed[$namespace])) {
                $reason = "source '{$class}' supplies the namespace '{$namespace}', which '{$claimed[$namespace]}' supplies too.";

                throw new InvalidAuthorizationConfigException(self::SOURCES . ".{$index}", $reason, IssueCode::DUPLICATE, 'a source supplying a namespace no other supplies');
            }

            $claimed[$namespace] = $class;
        }
    }

    /**
     * Refuse an entry of `context.sources` that is not a class implementing
     * `ContextSource`.
     *
     * @param  int|string  $index
     * @param  mixed  $class
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     *
     * @phpstan-assert class-string<\SineMacula\Laravel\Authorization\Contracts\ContextSource> $class
     */
    public static function source(int|string $index, mixed $class): void
    {
        [$issue, $reason] = match (true) {
            !\is_string($class) || $class === ''           => [IssueCode::INVALID_TYPE, 'entry must be a non-empty class-string, got ' . \get_debug_type($class) . '.'],
            !\class_exists($class)                         => [IssueCode::UNKNOWN_CLASS, "class '{$class}' does not exist."],
            !\is_subclass_of($class, ContextSource::class) => [IssueCode::NOT_IMPLEMENTED, "class '{$class}' does not implement " . ContextSource::class . '.'],
            default                                        => [null, ''],
        };

        if ($issue !== null) {
            $wanted = 'the name of a class implementing ' . ContextSource::class;

            throw new InvalidAuthorizationConfigException(self::SOURCES . ".{$index}", $reason, $issue, $wanted, \get_debug_type($class));
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
            throw new InvalidAuthorizationConfigException('authorization.context', $exception->getMessage(), IssueCode::INVALID_VALUE, 'assurance keys that are names');
        }

        foreach (\array_diff($authentication->namespaces(), ['authentication']) as $namespace) {
            if (!self::isClaimable($namespace) || isset($claimed[$namespace])) {
                $reason = 'authentication context \'' . $authentication::class . "' contributes the namespace '{$namespace}', which is not a name, is reserved ("
                    . \implode(', ', ContextSource::RESERVED_NAMESPACES) . ') or is listed twice.';

                $wanted = 'contributed namespaces that are names, not reserved and listed once';

                throw new InvalidAuthorizationConfigException('authorization.context', $reason, IssueCode::INVALID_VALUE, $wanted);
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
