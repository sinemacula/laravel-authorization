<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider;
use SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The attribute providers an application registers, by morph type (N30): those
 * of `authorization.attributes.resources` and
 * `authorization.attributes.subjects`.
 *
 * Each provider is resolved from the container the first time it is needed,
 * then kept. Its values are read afresh for every check that reads its
 * namespace, and only those of the keys it declares are exposed: a value it
 * returns for a key it does not declare is dropped. A provider that cannot be
 * resolved, or that throws, aborts the check with `AttributeProviderFailed`,
 * which carries none of its values or of its failure's message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AttributeProviders
{
    /** @var string The namespace resource attributes are read under. */
    public const string RESOURCE = 'resource';

    /** @var string The namespace subject attributes are read under. */
    public const string SUBJECT = 'subject';

    /** @var array<string, class-string> The contract a provider of each namespace implements. */
    public const array CONTRACTS = [
        self::RESOURCE => ResourceAttributeProvider::class,
        self::SUBJECT  => SubjectAttributeProvider::class,
    ];

    /** @var array<string, object> The providers resolved so far, by class. */
    private array $resolved = [];

    /** @var array<string, array<string, string>> The class of each namespace's provider, by morph type. */
    private readonly array $classes;

    /**
     * Create a new set of attribute providers.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  array<string, class-string<\SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider>>  $resources
     * @param  array<string, class-string<\SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider>>  $subjects
     */
    public function __construct(

        /** Container each provider is resolved from. */
        private readonly Container $container,

        // The resource attribute provider of each morph type.
        array $resources = [],

        // The subject attribute provider of each morph type.
        array $subjects = [],
    ) {
        $this->classes = [self::RESOURCE => $resources, self::SUBJECT => $subjects];
    }

    /**
     * Return the providers `authorization.attributes` registers, which the
     * service provider validated at boot.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return self
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function fromConfig(Container $container): self
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $container->make('config');

        /** @var array<string, class-string<\SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider>> $resources */
        $resources = (array) $config->get('authorization.attributes.resources', []);

        /** @var array<string, class-string<\SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider>> $subjects */
        $subjects = (array) $config->get('authorization.attributes.subjects', []);

        return new self($container, $resources, $subjects);
    }

    /**
     * Return the attributes every provider declares, keyed by namespace, then
     * by the provider's class, as the context key catalogue takes them.
     *
     * @return array<string, array<string, array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>>>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \UnexpectedValueException
     */
    public function declarations(): array
    {
        $declarations = [];

        foreach ($this->classes as $namespace => $classes) {
            foreach ($classes as $class) {
                $declarations[$namespace][$class] = $this->resolve($class, self::CONTRACTS[$namespace])->attributes();
            }
        }

        return $declarations;
    }

    /**
     * Return the attributes the provider of the resource's type supplies for
     * it, the declared ones only, given the model the check was given. A type
     * alone, an opaque identifier and a type with no provider have none.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     */
    public function resourceValues(ResourceReference $resource): array
    {
        $type = $resource->id === null ? null : $resource->type;

        return $this->read(self::RESOURCE, $type, function (string $class) use ($resource): array {
            $provider = $this->resolve($class, ResourceAttributeProvider::class);

            return self::declaredOnly($provider->values($resource, $resource->model), $provider->attributes());
        });
    }

    /**
     * Return the attributes the provider of the subject's morph type supplies
     * for it, the declared ones only. A type with no provider has none.
     *
     * @param  object  $subject
     * @param  string  $type
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     */
    public function subjectValues(object $subject, string $type): array
    {
        return $this->read(self::SUBJECT, $type, function (string $class) use ($subject): array {
            $provider = $this->resolve($class, SubjectAttributeProvider::class);

            return self::declaredOnly($provider->values($subject), $provider->attributes());
        });
    }

    /**
     * Read the attributes of the namespace's provider for the type, or none
     * when no provider is registered for it, turning any failure into
     * `AttributeProviderFailed`.
     *
     * @param  string  $namespace
     * @param  string|null  $type
     * @param  \Closure(string): array<string, mixed>  $read
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     */
    private function read(string $namespace, ?string $type, \Closure $read): array
    {
        $class = $type === null ? null : ($this->classes[$namespace][$type] ?? null);

        if ($class === null) {
            return [];
        }

        try {
            return $read($class);
        } catch (\Throwable $exception) {
            throw new AttributeProviderFailed($class, $namespace, $exception);
        }
    }

    /**
     * Return the provider of the class, resolved from the container the first
     * time, refusing one that does not implement the contract.
     *
     * @template TProvider of object
     *
     * @param  string  $class
     * @param  class-string<TProvider>  $contract
     * @return TProvider
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \UnexpectedValueException
     */
    private function resolve(string $class, string $contract): object
    {
        return self::implementing($class, $this->resolved[$class] ??= $this->container->make($class), $contract);
    }

    /**
     * Return the provider resolved for the class, refusing one that does not
     * implement the contract.
     *
     * @template TProvider of object
     *
     * @param  string  $class
     * @param  mixed  $provider
     * @param  class-string<TProvider>  $contract
     * @return TProvider
     *
     * @throws \UnexpectedValueException
     */
    private static function implementing(string $class, mixed $provider, string $contract): object
    {
        if (!$provider instanceof $contract) {
            throw new \UnexpectedValueException("Attribute provider '{$class}' does not implement {$contract}.");
        }

        return $provider;
    }

    /**
     * Return the values at the declared paths alone, nested as given, leaving
     * out every key the provider does not declare and every declared key it
     * leaves out.
     *
     * @param  array<array-key, mixed>  $values
     * @param  array<string, mixed>  $attributes
     * @return array<string, mixed>
     */
    private static function declaredOnly(array $values, array $attributes): array
    {
        $declared = [];

        foreach (\array_keys($attributes) as $path) {
            $segments = \explode('.', $path);
            $value    = $values;

            foreach ($segments as $segment) {
                if (!\is_array($value) || !\array_key_exists($segment, $value)) {
                    continue 2;
                }

                $value = $value[$segment];
            }

            $declared = \array_replace_recursive($declared, self::nest($segments, $value));
        }

        /** @var array<string, mixed> */
        return $declared;
    }

    /**
     * Nest the value under the path's segments, the first outermost.
     *
     * @param  list<string>  $segments
     * @param  mixed  $value
     * @return array<string, mixed>
     */
    private static function nest(array $segments, mixed $value): array
    {
        foreach (\array_reverse($segments) as $segment) {
            $value = [$segment => $value];
        }

        /** @var array<string, mixed> $value */
        return $value;
    }
}
