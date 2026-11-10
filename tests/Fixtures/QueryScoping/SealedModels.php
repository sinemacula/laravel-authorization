<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * Builds the queryable post models a query scope refuses: one overriding each
 * sealed method, one naming its own resource, ones with an accessor or a cast
 * on the key or a tenant column, and ones declaring tenant columns the table
 * lacks or cannot compare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class SealedModels
{
    /**
     * Return a queryable post overriding the method.
     *
     * @param  string  $method
     * @return \Illuminate\Database\Eloquent\Model
     *
     * @SuppressWarnings("php:S1172")
     */
    public static function overriding(string $method): Model
    {
        return match ($method) {
            'getMorphClass' => new class extends AbstractQueryablePost {
                /**
                 * Return the morph class, as the model's own.
                 *
                 * @return string
                 */
                #[\Override]
                public function getMorphClass(): string
                {
                    return parent::getMorphClass();
                }
            },
            'newFromBuilder' => new class extends AbstractQueryablePost {
                /**
                 * Build a model from a row, as the model's own.
                 *
                 * @param  array<string, mixed>  $attributes
                 * @param  string|\UnitEnum|null  $connection
                 * @return self
                 *
                 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
                 */
                #[\Override]
                public function newFromBuilder(mixed $attributes = [], mixed $connection = null): self
                {
                    return parent::newFromBuilder($attributes, $connection);
                }
            },
            'getKey' => new class extends AbstractQueryablePost {
                /**
                 * Return the key, as the model's own.
                 *
                 * @return mixed
                 *
                 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
                 */
                #[\Override]
                public function getKey(): mixed
                {
                    return parent::getKey();
                }
            },
            'getKeyName' => new class extends AbstractQueryablePost {
                /**
                 * Return the key's name, as the model's own.
                 *
                 * @return string
                 *
                 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
                 */
                #[\Override]
                public function getKeyName(): string
                {
                    return parent::getKeyName();
                }
            },
            'getAttribute' => new class extends AbstractQueryablePost {
                /**
                 * Return an attribute, as the model's own.
                 *
                 * @param  string  $key
                 * @return mixed
                 *
                 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
                 */
                #[\Override]
                public function getAttribute(mixed $key): mixed
                {
                    return parent::getAttribute($key);
                }
            },
            'getAttributes' => new class extends AbstractQueryablePost {
                /**
                 * Return the attributes, as the model's own.
                 *
                 * @return array<string, mixed>
                 *
                 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
                 */
                #[\Override]
                public function getAttributes(): array
                {
                    return parent::getAttributes();
                }
            },
            'getAttributeValue' => new class extends AbstractQueryablePost {
                /**
                 * Return an attribute's value, as the model's own.
                 *
                 * @param  string  $key
                 * @return mixed
                 *
                 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
                 */
                #[\Override]
                public function getAttributeValue(mixed $key): mixed
                {
                    return parent::getAttributeValue($key);
                }
            },
            default => new class extends AbstractQueryablePost {
                /**
                 * Set the raw attributes, as the model's own.
                 *
                 * @param  array<array-key, mixed>  $attributes
                 * @param  bool  $sync
                 * @return self
                 *
                 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
                 */
                #[\Override]
                public function setRawAttributes(array $attributes, mixed $sync = false): self
                {
                    return parent::setRawAttributes($attributes, $sync);
                }
            },
        };
    }

    /**
     * Return a queryable post that names its own resource.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    public static function namingItsResource(): Model
    {
        return new class extends AbstractQueryablePost implements AuthorizableResource {
            /**
             * Name a record of another type.
             *
             * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
             */
            #[\Override]
            public function toResourceReference(): ResourceReference
            {
                return ResourceReference::record('posts', '1');
            }
        };
    }

    /**
     * Return a queryable post with an accessor on its key, or on a tenant
     * column.
     *
     * @param  bool  $onKey
     * @return \Illuminate\Database\Eloquent\Model
     */
    public static function withAccessor(bool $onKey): Model
    {
        return $onKey
            ? new class extends AbstractQueryablePost {
                /**
                 * Read the key.
                 *
                 * @param  mixed  $value
                 * @return mixed
                 */
                public function getIdAttribute(mixed $value): mixed // @phpstan-ignore sineMaculaLaravel.modelBehaviour
                {
                    return $value;
                }
            }
        : new class extends AbstractQueryablePost {
            /**
             * Read the tenant's key.
             *
             * @return \Illuminate\Database\Eloquent\Casts\Attribute<mixed, never>
             */
            protected function tenantId(): Attribute
            {
                return Attribute::get(static fn (mixed $value): mixed => $value);
            }
        };
    }

    /**
     * Return a queryable post with the casts.
     *
     * @param  array<string, string>  $casts
     * @return \Illuminate\Database\Eloquent\Model
     */
    public static function withCasts(array $casts): Model
    {
        $model = new class extends AbstractQueryablePost {};

        return $model->mergeCasts($casts);
    }

    /**
     * Return a post declaring its tenant in the given columns.
     *
     * @param  string  $typeColumn
     * @param  string  $idColumn
     * @return \Illuminate\Database\Eloquent\Model
     */
    public static function withTenantColumns(string $typeColumn, string $idColumn): Model
    {
        AbstractQueryablePost::$tenancy = ResourceTenancy::columns($typeColumn, $idColumn);

        return new class extends AbstractQueryablePost {};
    }

    /**
     * Return a plain post that declares nothing.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    public static function undeclared(): Model
    {
        return new class extends Model {
            /** @var string|null Backing table. */
            protected $table = 'scoped_posts';
        };
    }
}
