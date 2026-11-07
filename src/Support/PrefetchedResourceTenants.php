<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Contracts\BulkResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;

/**
 * The tenants of a bulk check's resources, read at once (AUTHZ-4.4,
 * AUTHZ-10.3).
 *
 * Made for the resources of one chunk of a bulk check, it asks the bound
 * resolver, when it answers in bulk (`BulkResourceTenantResolver`), for the
 * tenant of every model and record among them that `ResourceReferences` would
 * ask it about: the models once, and the records of each type once, each record
 * read once however often it is named. It then answers as the bound resolver
 * would, from what it read, and asks the bound resolver itself about whatever
 * it did not read: everything, when the resolver does not answer in bulk, or a
 * call that threw, so a resource whose tenant cannot be told fails its own
 * check alone. A model is answered as the very model it was read for, since two
 * models with the same key may hold other attributes in memory.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PrefetchedResourceTenants implements ResourceTenantResolver
{
    /** @var \WeakMap<\Illuminate\Database\Eloquent\Model, array{\SineMacula\Laravel\Authorization\Support\Reference|null}> The tenant read for each model, held in a list of one, since a map holding null holds nothing. */
    private \WeakMap $models;

    /** @var array<string, false|\SineMacula\Laravel\Authorization\Support\Reference|null> The tenant read for each record, keyed by its type and key. */
    private array $records = [];

    /**
     * Create a new set of prefetched tenants, holding none yet.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver  $resolver
     */
    public function __construct(

        /** The bound resolver, which answers whatever was not read. */
        private readonly ResourceTenantResolver $resolver,
    ) {
        $this->models = new \WeakMap;
    }

    /**
     * Return the tenants of the values, read at once from the resolver when it
     * answers in bulk.
     *
     * @param  array<array-key, mixed>  $values
     * @param  \SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver  $resolver
     * @return self
     */
    public static function of(array $values, ResourceTenantResolver $resolver): self
    {
        $tenants = new self($resolver);

        if ($resolver instanceof BulkResourceTenantResolver) {
            $tenants->read($values, $resolver);
        }

        return $tenants;
    }

    /**
     * Return the tenant read for the model, or the bound resolver's answer when
     * none was.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $resource
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenantOf(Model $resource): ?Reference
    {
        return $this->models->offsetExists($resource) ? $this->models[$resource][0] : $this->resolver->tenantOf($resource);
    }

    /**
     * Return the tenant read for the record, or the bound resolver's answer
     * when none was.
     *
     * @param  string  $type
     * @param  string  $id
     * @return false|\SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenantOfRecord(string $type, string $id): false|Reference|null
    {
        $key = $type . "\0" . $id;

        return \array_key_exists($key, $this->records) ? $this->records[$key] : $this->resolver->tenantOfRecord($type, $id);
    }

    /**
     * Read the tenants of the models and records among the values from the
     * resolver: the models in one call and the records of each type in one
     * more. A call that throws reads nothing, so each resource it was asked
     * about is asked about on its own.
     *
     * @param  array<array-key, mixed>  $values
     * @param  \SineMacula\Laravel\Authorization\Contracts\BulkResourceTenantResolver  $resolver
     * @return void
     */
    private function read(array $values, BulkResourceTenantResolver $resolver): void
    {
        $models  = [];
        $records = [];
        $seen    = [];

        foreach ($values as $value) {
            if (self::isAskedAbout($value)) {
                $models[] = $value;

                continue;
            }

            $record = \is_array($value) ? ResourceReferences::recordOf($value) : false;

            if ($record === false) {
                continue;
            }

            // A record always has a type and a key.
            /** @var string $type */
            $type = $record->type;

            /** @var string $id */
            $id = $record->id;

            if (isset($seen["{$type}\0{$id}"])) {
                continue;
            }

            $seen["{$type}\0{$id}"]   = true;
            $records["#{$type}"][0]   = $type;
            $records["#{$type}"][1][] = $id;
        }

        $this->readModels($models, $resolver);

        foreach ($records as [$type, $ids]) {
            $this->readRecords($type, $ids, $resolver);
        }
    }

    /**
     * Read the tenants of the models in one call, keeping each answer the
     * resolver gives.
     *
     * @param  list<\Illuminate\Database\Eloquent\Model>  $models
     * @param  \SineMacula\Laravel\Authorization\Contracts\BulkResourceTenantResolver  $resolver
     * @return void
     */
    private function readModels(array $models, BulkResourceTenantResolver $resolver): void
    {
        if ($models === []) {
            return;
        }

        try {
            $tenants = $resolver->tenantsOf($models);
        } catch (\Throwable) {
            return;
        }

        foreach ($models as $index => $model) {
            if (!\array_key_exists($index, $tenants)) {
                continue;
            }

            $this->models[$model] = [$tenants[$index]];
        }
    }

    /**
     * Read the tenants of the records of the type in one call, keeping each
     * answer the resolver gives.
     *
     * @param  string  $type
     * @param  list<string>  $ids
     * @param  \SineMacula\Laravel\Authorization\Contracts\BulkResourceTenantResolver  $resolver
     * @return void
     */
    private function readRecords(string $type, array $ids, BulkResourceTenantResolver $resolver): void
    {
        try {
            $tenants = $resolver->tenantsOfRecords($type, $ids);
        } catch (\Throwable) {
            return;
        }

        foreach ($ids as $index => $id) {
            if (!\array_key_exists($index, $tenants)) {
                continue;
            }

            $this->records[$type . "\0" . $id] = $tenants[$index];
        }
    }

    /**
     * Determine whether `ResourceReferences` asks the resolver about the
     * value's tenant as a model: a model with a key, not one that names its own
     * resource.
     *
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true \Illuminate\Database\Eloquent\Model $value
     */
    private static function isAskedAbout(mixed $value): bool
    {
        if (!$value instanceof Model || $value instanceof AuthorizableResource) {
            return false;
        }

        $key = $value->getKey();

        return \is_scalar($key) && $key !== '';
    }
}
