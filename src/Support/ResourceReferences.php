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
     * tenant resolver, and a model's reference keeps the model, as does the
     * record a model's own resource contract names; a model class names its
     * type alone; a pair names one record; any other string, or object that can
     * be cast to one, is an opaque identifier.
     *
     * An identifier holding a NUL byte names nothing, so it cannot be
     * identified either, however it was given: a string, a pair, a model's key,
     * a resource's own reference or a reference built directly, as the route
     * middleware builds one for a raw parameter. It never reaches a pattern
     * match.
     *
     * A bulk check gives the tenants it has read for its resources at once, in
     * place of the bound resolver, which answers whatever they leave out.
     *
     * @param  mixed  $value
     * @param  \SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver|null  $tenants
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null
     */
    public static function of(mixed $value, ?ResourceTenantResolver $tenants = null): false|ResourceReference|null
    {
        $reference = match (true) {
            $value === null                                            => null,
            $value instanceof ResourceReference                        => $value,
            $value instanceof AuthorizableResource                     => self::ofResource($value),
            $value instanceof Model                                    => self::ofModel($value, $tenants),
            \is_string($value)                                         => self::ofString($value),
            \is_array($value)                                          => self::ofPair($value, $tenants),
            \is_object($value) && \method_exists($value, '__toString') => new ResourceReference((string) $value),
            default                                                    => false,
        };

        return $reference instanceof ResourceReference && \str_contains($reference->identifier, "\0") ? false : $reference;
    }

    /**
     * Return the identifier a resolved reference carries, or null for no
     * resource or one that cannot be identified, as a decision's events report
     * it.
     *
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $reference
     * @return string|null
     */
    public static function identifierOf(false|ResourceReference|null $reference): ?string
    {
        return $reference === false ? null : $reference?->identifier;
    }

    /**
     * Return the reference to the record a `(type, id)` pair names, without a
     * tenant and without asking the bound resource tenant resolver, or false
     * when it is not a type and a non-empty string or number, either holds a
     * NUL byte, or it names an abstract model class. A model class names its
     * type as the model's morph class, as the model itself would.
     *
     * The resource policy service names a record this way, since where an
     * attachment holds comes from the call, not from the record's tenant.
     *
     * @param  array<mixed>  $pair
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    public static function recordOf(array $pair): false|ResourceReference
    {
        [$type, $id] = \array_is_list($pair) && \count($pair) === 2 ? $pair : [null, null];

        $type = \is_string($type) && $type !== '' && !\str_contains($type, "\0") ? self::typeOf($type) : null;

        if ($type === null || !self::isKey($id)) {
            return false;
        }

        /** @var float|int|string $id */
        return ResourceReference::record($type, (string) $id);
    }

    /**
     * Return the reference the resource's contract gives, handing on the
     * resource itself when it is a model and the contract names one record
     * without a model, so its type's resource attribute provider can read the
     * model rather than query for it. The contract still decides the record and
     * its tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizableResource  $resource
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    private static function ofResource(AuthorizableResource $resource): ResourceReference
    {
        $reference = $resource->toResourceReference();

        if (!$resource instanceof Model || $reference->id === null || $reference->model !== null) {
            return $reference;
        }

        return new ResourceReference($reference->identifier, $reference->type, $reference->id, $reference->tenant, $resource);
    }

    /**
     * Return the reference to a saved model, with its tenant and the model
     * itself, or false when it has no key.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver|null  $tenants
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    private static function ofModel(Model $model, ?ResourceTenantResolver $tenants): false|ResourceReference
    {
        $key = $model->getKey();

        if (!\is_scalar($key) || $key === '') {
            return false;
        }

        return ResourceReference::record($model->getMorphClass(), (string) $key, ($tenants ?? self::resolver())->tenantOf($model), $model);
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
     * The resolver is never asked about a type or id holding a NUL byte.
     *
     * @param  array<mixed>  $pair
     * @param  \SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver|null  $tenants
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    private static function ofPair(array $pair, ?ResourceTenantResolver $tenants): false|ResourceReference
    {
        $record = self::recordOf($pair);

        if ($record === false) {
            return false;
        }

        /** @var string $type */
        $type   = $record->type;
        $id     = (string) $record->id;
        $tenant = ($tenants ?? self::resolver())->tenantOfRecord($type, $id);

        return $tenant === false ? false : ResourceReference::record($type, $id, $tenant);
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
