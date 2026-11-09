<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ContextSource;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Evaluation\PolicyValidator;

/**
 * The context keys declared to the package: its own, those given at
 * construction (the `authorization.context.keys` configuration and the
 * attribute providers' declarations) and those an application or sibling
 * package registers from a service provider.
 *
 * The catalogue lives in the container, one per application, and holds no
 * static state: what one registers is seen by every policy written after it. A
 * key is a full dot path of at least two segments, the namespace first, each in
 * the condition key syntax, of at most `PolicyValidator::KEY_LENGTH`
 * characters.
 *
 * The keys of `subject` and `resource` (N29) are the package's built-ins (`id`,
 * `type`, `tenant.type` and `tenant.id`) and those the attribute providers
 * declare, given at construction; neither namespace takes a key declared or
 * registered any other way, and no provider may declare a built-in, a key under
 * one, or a key under another key it declares.
 *
 * An assurance key (see `AssuranceKeys`) of `authentication` or of a namespace
 * the authentication context contributes, under the fixed names or those the
 * context declares, is always untestable, whatever its declaration says (N37,
 * N104), so declaring it testable again changes nothing.
 *
 * The authentication context's namespaces and assurance keys are read at the
 * catalogue's first use that needs them (a key found, permitted or listed, or a
 * key declared again with another testability), never when it is built, and
 * once: a context a service provider binds after the catalogue was built, as
 * long as it is bound before that first use, is the one read. They must stay
 * the same for the life of the process.
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
        'resource.id'              => 'string',
        'resource.tenant.id'       => 'string',
        'resource.tenant.type'     => 'string',
        'resource.type'            => 'string',
        'subject.id'               => 'string',
        'subject.tenant.id'        => 'string',
        'subject.tenant.type'      => 'string',
        'subject.type'             => 'string',
    ];

    /** @var list<string> The first segments of the built-in `subject` and `resource` keys, under which no attribute provider may declare a key. */
    public const array BUILT_IN_ATTRIBUTES = ['id', 'type', 'tenant'];

    /** @var array<string, \SineMacula\Laravel\Authorization\Context\ContextKey> Every declared key, by dot path. */
    private array $keys = [];

    /** @var \Closure(): \SineMacula\Laravel\Authorization\Context\AssuranceKeys Reads the authentication context's assurance keys at first use. */
    private readonly \Closure $assuranceSource;

    /** @var \SineMacula\Laravel\Authorization\Context\AssuranceKeys|null The authentication context's assurance keys, once read. */
    private ?AssuranceKeys $assurance = null;

    /**
     * Create a new declared context key catalogue with the package's keys, the
     * given ones and the attributes the providers declare.
     *
     * The attributes are keyed by namespace (`subject` or `resource`), then by
     * the provider's class, each a map of dot paths within the namespace to
     * their types, as the provider's `attributes()` returns them. The assurance
     * keys are those of the authentication context, untestable like those of
     * `authentication`: given as they are, as the namespaces it contributes
     * beside `authentication` under the fixed names alone, or as a closure the
     * catalogue calls at its first use that needs them.
     *
     * @param  array<string, array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>>  $keys
     * @param  array<string, array<string, array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>>>  $attributes
     * @param  (\Closure(): \SineMacula\Laravel\Authorization\Context\AssuranceKeys)|list<string>|\SineMacula\Laravel\Authorization\Context\AssuranceKeys  $assurance
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(array $keys = [], array $attributes = [], array|AssuranceKeys|\Closure $assurance = [])
    {
        $given                 = \is_array($assurance) ? new AssuranceKeys($assurance) : $assurance;
        $this->assuranceSource = $given instanceof \Closure ? $given : static fn (): AssuranceKeys => $given;

        foreach (self::PACKAGE_KEYS as $path => $type) {
            $this->put($path, ContextKeyType::from($type), true);
        }

        foreach ($keys as $namespace => $namespaceKeys) {
            $this->register($namespace, $namespaceKeys);
        }

        foreach ($attributes as $namespace => $providers) {
            foreach ($providers as $provider => $providerKeys) {
                $this->declareAttributes($namespace, $provider, $providerKeys);
            }
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
        self::assertValidPath($path);
        self::assertOutsideAttributes($path);

        $this->put($path, $type, $isTestable);
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
        $key = $this->find($path);

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
        $key = $this->keys[$path] ?? null;

        return $key === null ? null : $this->effective($key);
    }

    /**
     * Return every declared key, by its dot path, in order of path.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Context\ContextKey>
     */
    #[\Override]
    public function keys(): array
    {
        $keys = \array_map($this->effective(...), $this->keys);

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
        $namespaces = \array_unique(\array_map(static fn (ContextKey $key): string => $key->namespace(), $this->keys));

        \sort($namespaces, \SORT_STRING);

        return $namespaces;
    }

    /**
     * Declare a key, refusing one already declared with another type or
     * testability. An assurance key is untestable whatever it is declared as,
     * so declaring one again with another testability is accepted and changes
     * nothing.
     *
     * The key is held as declared, and made untestable when it is read (see
     * `effective()`), so the authentication context's assurance keys are read
     * only when a key is read, or declared again with another testability.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\Authorization\Enums\ContextKeyType  $type
     * @param  bool  $isTestable
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function put(string $path, ContextKeyType $type, bool $isTestable): void
    {
        $declared = $this->keys[$path] ?? null;

        if ($declared !== null && ($declared->type !== $type || ($declared->isTestable !== $isTestable && !$this->assurance()->matches($path)))) {
            $shown = $this->effective($declared);

            throw new \InvalidArgumentException("Context key '{$path}' is already declared as {$shown->type->value}" . ($shown->isTestable ? '' : ', untestable') . '.');
        }

        $this->keys[$path] = $declared ?? new ContextKey($path, $type, $isTestable);
    }

    /**
     * Return the key as a policy may read it: untestable when it is an
     * assurance key, whatever it was declared as, and as declared otherwise.
     *
     * @param  \SineMacula\Laravel\Authorization\Context\ContextKey  $key
     * @return \SineMacula\Laravel\Authorization\Context\ContextKey
     */
    private function effective(ContextKey $key): ContextKey
    {
        return $key->isTestable && $this->assurance()->matches($key->path) ? new ContextKey($key->path, $key->type, false) : $key;
    }

    /**
     * Return the authentication context's assurance keys, read at the first
     * call and kept. A read that fails is not kept, so every use fails closed.
     *
     * @return \SineMacula\Laravel\Authorization\Context\AssuranceKeys
     */
    private function assurance(): AssuranceKeys
    {
        return $this->assurance ??= ($this->assuranceSource)();
    }

    /**
     * Declare the attributes a provider supplies under `subject` or `resource`,
     * refusing another namespace, a built-in or a key under one, a key another
     * provider declares with another type, and a key under another key the
     * provider declares.
     *
     * @param  string  $namespace
     * @param  string  $provider
     * @param  array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>  $keys
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function declareAttributes(string $namespace, string $provider, array $keys): void
    {
        if (!\in_array($namespace, ContextSource::ATTRIBUTE_NAMESPACES, true)) {
            throw new \InvalidArgumentException("Attribute provider {$provider} supplies the namespace '{$namespace}'; attributes belong under 'subject' or 'resource'.");
        }

        foreach ($keys as $path => $type) {
            $key = "{$namespace}.{$path}";

            self::assertValidPath($key);

            if (\in_array(\explode('.', $path)[0], self::BUILT_IN_ATTRIBUTES, true)) {
                $reason = 'is a built-in or under one; no provider may declare \'id\', \'type\' or \'tenant\'.';

                throw new \InvalidArgumentException("Attribute provider {$provider} declares '{$key}', which {$reason}");
            }

            $type     = self::typeOf($key, $type);
            $declared = $this->keys[$key] ?? null;

            if ($declared !== null && $declared->type !== $type) {
                $reason = "but another provider declares it as {$declared->type->value}.";

                throw new \InvalidArgumentException("Attribute provider {$provider} declares '{$key}' as {$type->value}, {$reason}");
            }

            $this->put($key, $type, true);
        }

        self::assertNoKeyUnderAnother($namespace, $provider, $keys);
    }

    /**
     * Refuse a provider that declares a key under another key it declares, such
     * as `owner` and `owner.id`: the value of the outer key could only be a
     * map, which is never exposed, so the inner key could never be read.
     *
     * @param  string  $namespace
     * @param  string  $provider
     * @param  array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>  $keys
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertNoKeyUnderAnother(string $namespace, string $provider, array $keys): void
    {
        foreach (\array_keys($keys) as $path) {
            $parent = $path;

            while (($end = \strrpos($parent, '.')) !== false) {
                $parent = \substr($parent, 0, $end);

                if (\array_key_exists($parent, $keys)) {
                    $reason = "which it also declares; declare the keys under '{$namespace}.{$parent}' alone.";

                    throw new \InvalidArgumentException("Attribute provider {$provider} declares '{$namespace}.{$path}' under '{$namespace}.{$parent}', {$reason}");
                }
            }
        }
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
     * Refuse a path under `subject` or `resource`, whose keys are the package's
     * built-ins and those the attribute providers declare, so a key declared
     * any other way could only ever be found missing.
     *
     * @param  string  $path
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertOutsideAttributes(string $path): void
    {
        $namespace = ContextKey::namespaceOf($path);

        if (\in_array($namespace, ContextSource::ATTRIBUTE_NAMESPACES, true)) {
            $reason = "is under the namespace '{$namespace}', whose keys are the package's built-ins and those an attribute provider declares; "
                . 'register a provider in authorization.attributes.subjects or authorization.attributes.resources.';

            throw new \InvalidArgumentException("Context key '{$path}' {$reason}");
        }
    }

    /**
     * Refuse a path that is not a namespace and at least one more segment, in
     * the condition key syntax and not too long.
     *
     * @param  string  $path
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertValidPath(string $path): void
    {
        $isValid = \str_contains($path, '.')
            && \strlen($path) <= PolicyValidator::KEY_LENGTH
            && \preg_match(PolicyValidator::KEY_PATTERN, $path) === 1;

        if (!$isValid) {
            $syntax = 'a namespace and one or more \'.\'-separated segments of letters, digits, \'_\' and \'-\'';

            throw new \InvalidArgumentException("Context key '{$path}' must be {$syntax}, and at most " . PolicyValidator::KEY_LENGTH . ' characters.');
        }
    }
}
