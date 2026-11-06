<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Context\AttributeProviders;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AttributeConfigValidator
{
    /** @var string The config key of the attribute providers. */
    private const string ATTRIBUTES = 'authorization.attributes';

    /** @var array<string, string> The namespace each config key's providers supply. */
    private const array NAMESPACES = [
        'resources' => AttributeProviders::RESOURCE,
        'subjects'  => AttributeProviders::SUBJECT,
    ];

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
        if (!\is_array($config)) {
            throw new InvalidAuthorizationConfigException(self::ATTRIBUTES, 'expected an array with resources and subjects, got ' . \get_debug_type($config) . '.');
        }

        $providers = [];

        foreach (self::NAMESPACES as $key => $namespace) {
            $providers[$key] = self::providersOf($key, $config[$key] ?? [], AttributeProviders::CONTRACTS[$namespace]);
        }

        /** @var array<string, class-string<\SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider>> $resources */
        $resources = $providers['resources'];

        /** @var array<string, class-string<\SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider>> $subjects */
        $subjects = $providers['subjects'];

        try {
            $declarations = (new AttributeProviders($container, $resources, $subjects))->declarations();
        } catch (BindingResolutionException|\UnexpectedValueException $exception) {
            throw new InvalidAuthorizationConfigException(self::ATTRIBUTES, 'a provider could not be resolved from the container: ' . $exception->getMessage());
        }

        self::validateDeclarations($declarations);
    }

    /**
     * Return the entries of `attributes.resources` or `attributes.subjects`,
     * refusing one that does not map a morph type to a class implementing the
     * contract.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  class-string  $contract
     * @return array<string, class-string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function providersOf(string $key, mixed $value, string $contract): array
    {
        $configKey = self::ATTRIBUTES . ".{$key}";

        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException($configKey, 'expected an array of morph types to class names, got ' . \get_debug_type($value) . '.');
        }

        foreach ($value as $type => $class) {
            self::validateProvider($configKey, $type, $class, $contract);
        }

        /** @var array<string, class-string> */
        return $value;
    }

    /**
     * Validate that one entry maps a morph type to a class implementing the
     * contract.
     *
     * @param  string  $configKey
     * @param  int|string  $type
     * @param  mixed  $class
     * @param  class-string  $contract
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateProvider(string $configKey, int|string $type, mixed $class, string $contract): void
    {
        if (!\is_string($type) || $type === '') {
            throw new InvalidAuthorizationConfigException($configKey, 'each entry must be keyed by a morph type, such as [\'post\' => PostAttributes::class].');
        }

        if (!\is_string($class) || !\class_exists($class) || !\is_subclass_of($class, $contract)) {
            $reason = 'expected the name of a class implementing ' . $contract . ', got ' . (\is_string($class) ? "'{$class}'" : \get_debug_type($class)) . '.';

            throw new InvalidAuthorizationConfigException("{$configKey}.{$type}", $reason);
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

                    throw new InvalidAuthorizationConfigException(self::ATTRIBUTES, $reason);
                }
            }
        }

        try {
            new DeclaredContextKeyCatalogue([], $declarations);
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidAuthorizationConfigException(self::ATTRIBUTES, $exception->getMessage());
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
