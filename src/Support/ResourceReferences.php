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
     * model's tenant comes from the bound resource tenant resolver; a model
     * class names its type alone; a `(type, id)` pair names one record; any
     * other string, or object that can be cast to one, is an opaque identifier.
     *
     * @param  mixed  $value
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null
     */
    public static function of(mixed $value): false|ResourceReference|null
    {
        return match (true) {
            $value === null                                            => null,
            $value instanceof ResourceReference                        => $value,
            $value instanceof AuthorizableResource                     => $value->toResourceReference(),
            $value instanceof Model                                    => self::ofModel($value),
            \is_string($value)                                         => self::ofString($value),
            \is_array($value)                                          => self::ofPair($value),
            \is_object($value) && \method_exists($value, '__toString') => new ResourceReference((string) $value),
            default                                                    => false,
        };
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
     * Return the reference to a model class's type, or an opaque identifier for
     * any other string.
     *
     * @param  string  $value
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    private static function ofString(string $value): ResourceReference
    {
        return \is_subclass_of($value, Model::class) ? ResourceReference::type((new $value)->getMorphClass()) : new ResourceReference($value);
    }

    /**
     * Return the reference to the record a `(type, id)` pair names, or false
     * when it is not two non-empty strings or numbers.
     *
     * @param  array<mixed>  $pair
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    private static function ofPair(array $pair): false|ResourceReference
    {
        if (!\array_is_list($pair) || \count($pair) !== 2) {
            return false;
        }

        [$type, $id] = $pair;

        if (!\is_string($type) || $type === '' || !self::isKey($id)) {
            return false;
        }

        /** @var float|int|string $id */
        return ResourceReference::record($type, (string) $id);
    }

    /**
     * Determine whether a pair's id is a key: a string or number, not empty.
     *
     * @param  mixed  $id
     * @return bool
     */
    private static function isKey(mixed $id): bool
    {
        return \is_scalar($id) && !\is_bool($id) && (string) $id !== '';
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
