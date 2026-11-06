<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;

/**
 * Turns the value a check is about into the reference of its resource
 * (AUTHZ-4.2), the one place every surface does it: `check()` and its adapters,
 * the Gate and the `authorize` route middleware.
 *
 * A model class is read through reflection without running its constructor, so
 * its own `getMorphClass()` names the type exactly as its models do, and no
 * constructor or boot side effect runs for a check (hence php:S3011).
 *
 * @SuppressWarnings("php:S3011")
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResourceReferences
{
    /**
     * Return the reference to the value's resource.
     *
     * Returns null for a null value (no resource) and false for a value that
     * cannot be identified, such as an unsaved model, a number or an empty
     * pair, so the check denies instead of matching every resource-less
     * statement. The resource contract wins over a model's own `type:id`; a
     * model's or a `(type, id)` pair's tenant comes from the bound resource
     * tenant resolver; a model class names its type alone; a pair names one
     * record; any other string, or object that can be cast to one, is an opaque
     * identifier.
     *
     * An identifier holding a NUL byte names nothing, so it cannot be
     * identified either, however it was given: a string, a pair, a model's key,
     * a resource's own reference or a reference built directly, as the route
     * middleware builds one for a raw parameter. It never reaches a pattern
     * match.
     *
     * @param  mixed  $value
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null
     */
    public static function of(mixed $value): false|ResourceReference|null
    {
        $reference = match (true) {
            $value === null                                            => null,
            $value instanceof ResourceReference                        => $value,
            $value instanceof AuthorizableResource                     => $value->toResourceReference(),
            $value instanceof Model                                    => self::ofModel($value),
            \is_string($value)                                         => self::ofString($value),
            \is_array($value)                                          => self::ofPair($value),
            \is_object($value) && \method_exists($value, '__toString') => new ResourceReference((string) $value),
            default                                                    => false,
        };

        return $reference instanceof ResourceReference && \str_contains($reference->identifier, "\0") ? false : $reference;
    }

    /**
     * Return the reference to a saved model, with its tenant, or false when it
     * has no key.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    private static function ofModel(Model $model): false|ResourceReference
    {
        $key = $model->getKey();

        if (!\is_scalar($key) || $key === '') {
            return false;
        }

        return ResourceReference::record($model->getMorphClass(), (string) $key, self::resolver()->tenantOf($model));
    }

    /**
     * Return the reference to a model class's type, false for an abstract model
     * class, or an opaque identifier for any other string.
     *
     * @param  string  $value
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    private static function ofString(string $value): false|ResourceReference
    {
        if (!\is_subclass_of($value, Model::class)) {
            return new ResourceReference($value);
        }

        $type = self::typeOf($value);

        return $type === null ? false : ResourceReference::type($type);
    }

    /**
     * Return the reference to the record a `(type, id)` pair names, with the
     * tenant the bound resource tenant resolver gives it, or false when it is
     * not a type and a non-empty string or number, either holds a NUL byte,
     * names an abstract model class, or the resolver cannot tell its tenant.
     * The resolver is never asked about a type or id holding a NUL byte. A
     * model class names its type as the model's morph class, as the model
     * itself would.
     *
     * @param  array<mixed>  $pair
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    private static function ofPair(array $pair): false|ResourceReference
    {
        [$type, $id] = \array_is_list($pair) && \count($pair) === 2 ? $pair : [null, null];

        $type = \is_string($type) && $type !== '' && !\str_contains($type, "\0") ? self::typeOf($type) : null;

        if ($type === null || !self::isKey($id)) {
            return false;
        }

        /** @var float|int|string $id */
        $tenant = self::resolver()->tenantOfRecord($type, (string) $id);

        return $tenant === false ? false : ResourceReference::record($type, (string) $id, $tenant);
    }

    /**
     * Return the type a string names: a model class's morph class, read without
     * running the model's constructor, null for an abstract model class, or the
     * string itself for anything else.
     *
     * @param  string  $type
     * @return string|null
     */
    private static function typeOf(string $type): ?string
    {
        if (!\is_subclass_of($type, Model::class)) {
            return $type;
        }

        $class = new \ReflectionClass($type);

        return $class->isAbstract() ? null : $class->newInstanceWithoutConstructor()->getMorphClass();
    }

    /**
     * Determine whether a pair's id is a key: a string or number, not empty and
     * without a NUL byte.
     *
     * @param  mixed  $id
     * @return bool
     */
    private static function isKey(mixed $id): bool
    {
        return \is_scalar($id) && !\is_bool($id) && $id !== '' && !\str_contains((string) $id, "\0");
    }

    /**
     * Return the bound resource tenant resolver.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver
     */
    private static function resolver(): ResourceTenantResolver
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver */
        return Container::getInstance()->make(ResourceTenantResolver::class);
    }
}
