<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Context\AttributeProviders;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Boot-time validator for the `authorization.attributes` config (N30), run by
 * `ConfigValidator`.
 *
 * `attributes.resources` and `attributes.subjects` must each map a morph type
 * to a class implementing `ResourceAttributeProvider` or
 * `SubjectAttributeProvider`. Each provider must resolve from the container, as
 * one implementing its contract, to read the attributes it declares, which must
 * map dot paths to the names of types and be accepted by the context key
 * catalogue: a valid path, a known type, not a built-in (`id`, `type`, or under
 * `tenant`), no key another provider declares with another type, and no key
 * under another key the same provider declares.
 *
 * The block sets no key but `resources` and `subjects` (N116); each is empty
 * when left out, and refused when set to null.
 *
 * The check of each entry's shape (`providers()`, `provider()`) builds nothing
 * and can run alone, as the configuration report runs it; the check of what the
 * providers declare (`declarations()`) builds each provider, so it runs at boot
 * only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AttributeConfigValidator
{
    /** @var list<string> The settings the block may set. */
    public const array SETTINGS = ['resources', 'subjects'];

    /** @var array<string, string> The namespace each config key's providers supply. */
    public const array NAMESPACES = [
        'resources' => AttributeProviders::RESOURCE,
        'subjects'  => AttributeProviders::SUBJECT,
    ];

    /** @var string The config key of the attribute providers. */
    private const string ATTRIBUTES = 'authorization.attributes';

    /**
     * Validate the supplied `attributes` config, throwing on the first failure.
     *
     * @param  mixed  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config, Container $container): void
    {
        $block     = ConfigBlock::of(self::ATTRIBUTES, $config, self::SETTINGS);
        $providers = [];

        foreach (self::NAMESPACES as $key => $namespace) {
            $providers[$key] = self::providers($key, ConfigBlock::entry($block, $key, []), AttributeProviders::CONTRACTS[$namespace]);
        }

        /** @var array<string, class-string<\SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider>> $resources */
        $resources = $providers['resources'];

        /** @var array<string, class-string<\SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider>> $subjects */
        $subjects = $providers['subjects'];

        self::declarations($resources, $subjects, $container);
    }

    /**
     * Validate that every provider resolves and declares its attributes as dot
     * paths mapped to types the context key catalogue accepts. Each provider is
     * built to read them, so this runs at boot only.
     *
     * @param  array<string, class-string<\SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider>>  $resources
     * @param  array<string, class-string<\SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider>>  $subjects
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function declarations(array $resources, array $subjects, Container $container): void
    {
        try {
            $declarations = (new AttributeProviders($container, $resources, $subjects))->declarations();
        } catch (BindingResolutionException|\UnexpectedValueException $exception) {
            $reason = 'a provider could not be resolved from the container: ' . $exception->getMessage();

            throw new InvalidAuthorizationConfigException(self::ATTRIBUTES, $reason, IssueCode::INVALID_VALUE, 'providers that resolve from the container');
        }

        self::validateDeclarations($declarations);
    }

    /**
     * Return the entries of `attributes.resources` or `attributes.subjects`,
     * refusing one that does not map a morph type to a class implementing the
     * contract. The attribute providers are read through here at run time too,
     * before any is resolved, so an entry changed after boot is refused there,
     * never cast.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  class-string  $contract
     * @return array<string, class-string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function providers(string $key, mixed $value, string $contract): array
    {
        $entry = static function (int|string $type, mixed $class) use ($key, $contract): void {
            self::provider($key, $type, $class, $contract);
        };

        /** @var array<string, class-string> */
        return ConfigBlock::entries(self::ATTRIBUTES . ".{$key}", $value, 'an array of morph types to class names', $entry);
    }

    /**
     * Validate that one entry of `attributes.resources` or
     * `attributes.subjects` maps a morph type to a class implementing the
     * contract.
     *
     * @param  string  $key
     * @param  int|string  $type
     * @param  mixed  $class
     * @param  class-string  $contract
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function provider(string $key, int|string $type, mixed $class, string $contract): void
    {
        $configKey = self::ATTRIBUTES . ".{$key}";
        $expected  = "a morph type mapped to the name of a class implementing {$contract}";

        if (!\is_string($type) || $type === '') {
            $reason = 'each entry must be keyed by a morph type, such as [\'post\' => PostAttributes::class].';

            throw new InvalidAuthorizationConfigException($configKey, $reason, IssueCode::INVALID_VALUE, $expected, \get_debug_type($class));
        }

        $wanted = "expected the name of a class implementing {$contract}, got ";

        [$issue, $reason] = match (true) {
            !\is_string($class)                 => [IssueCode::INVALID_TYPE, $wanted . \get_debug_type($class) . '.'],
            !\class_exists($class)              => [IssueCode::UNKNOWN_CLASS, "{$wanted}'{$class}'."],
            !\is_subclass_of($class, $contract) => [IssueCode::NOT_IMPLEMENTED, "{$wanted}'{$class}'."],
            default                             => [null, ''],
        };

        if ($issue !== null) {
            throw new InvalidAuthorizationConfigException("{$configKey}.{$type}", $reason, $issue, $expected, \get_debug_type($class));
        }
    }

    /**
     * Validate that every provider declares a map of dot paths to types, and
     * that the context key catalogue accepts every declaration.
     *
     * @param  array<string, array<string, array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>>>  $declarations
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateDeclarations(array $declarations): void
    {
        foreach ($declarations as $providers) {
            foreach ($providers as $class => $attributes) {
                if (!self::isTypeMap($attributes)) {
                    $reason = "provider '{$class}' must declare its attributes as dot paths mapped to the names of their types, such as ['status' => 'string'].";

                    $wanted = 'attributes declared as dot paths mapped to the names of their types';

                    throw new InvalidAuthorizationConfigException(self::ATTRIBUTES, $reason, IssueCode::INVALID_VALUE, $wanted);
                }
            }
        }

        try {
            new DeclaredContextKeyCatalogue([], $declarations);
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidAuthorizationConfigException(self::ATTRIBUTES, $exception->getMessage(), IssueCode::INVALID_VALUE, 'attributes the context key catalogue accepts');
        }
    }

    /**
     * Determine whether the value maps key paths to types or the names of
     * types.
     *
     * @param  mixed  $attributes
     * @return bool
     */
    private static function isTypeMap(mixed $attributes): bool
    {
        return \is_array($attributes) && \array_filter(
            $attributes,
            static fn (mixed $type, int|string $path): bool => !\is_string($path) || !(\is_string($type) || $type instanceof ContextKeyType),
            \ARRAY_FILTER_USE_BOTH,
        ) === [];
    }
}
