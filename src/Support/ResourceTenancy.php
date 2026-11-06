<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Model;

/**
 * Where a queryable model's records keep their tenant (AUTHZ-4.4, AUTHZ-10.1):
 * nowhere, for a tenantless model; in a type column and an id column; or in an
 * id column alone, every record's tenant being of one type.
 *
 * A record's tenant is read from its raw attributes, with no accessor and no
 * cast, as the database holds them: a record whose type or id is null has no
 * tenant, as `Reference::tenantOf()` reads an owner, and one whose declared
 * column is missing, as a partly selected model's may be, or holds anything but
 * a string or an integer, cannot be read, so a check on it throws rather than
 * deciding it as a record of no tenant (N10).
 *
 * A fixed type given as a model class is that model's morph class, read without
 * running its constructor (hence php:S3011).
 *
 * @SuppressWarnings("php:S3011")
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResourceTenancy
{
    /**
     * Create a new tenancy declaration.
     *
     * @param  string|null  $typeColumn
     * @param  string|null  $idColumn
     * @param  string|null  $type
     */
    private function __construct(

        /** The column holding the tenant's morph type; null when there is none. */
        public ?string $typeColumn = null,

        /** The column holding the tenant's key; null for a tenantless model. */
        public ?string $idColumn = null,

        /** The morph type every record's tenant has, when no column holds it. */
        public ?string $type = null,
    ) {}

    /**
     * Declare that the model's records have no tenant.
     *
     * @return self
     */
    public static function tenantless(): self
    {
        return new self;
    }

    /**
     * Declare that the model's records keep their tenant's morph type and key
     * in the given columns.
     *
     * @param  string  $typeColumn
     * @param  string  $idColumn
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function columns(string $typeColumn = 'tenant_type', string $idColumn = 'tenant_id'): self
    {
        return new self(self::column($typeColumn), self::column($idColumn));
    }

    /**
     * Declare that every record's tenant is of the given type, a morph type or
     * a model class, and that its key is in the given column.
     *
     * @param  string  $tenantType
     * @param  string  $idColumn
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function ofType(string $tenantType, string $idColumn): self
    {
        $type = \is_subclass_of($tenantType, Model::class)
            ? (new \ReflectionClass($tenantType))->newInstanceWithoutConstructor()->getMorphClass()
            : $tenantType;

        if ($type === '' || \strlen($type) > Reference::MAX_BYTES || \str_contains($type, "\0")) {
            throw new \InvalidArgumentException('A tenant type is 1 to ' . Reference::MAX_BYTES . ' bytes with no NUL byte.');
        }

        return new self(null, self::column($idColumn), $type);
    }

    /**
     * Determine whether the model's records have no tenant.
     *
     * @return bool
     */
    public function isTenantless(): bool
    {
        return $this->idColumn === null;
    }

    /**
     * Return the columns the tenant is kept in, the type column first.
     *
     * @return list<string>
     */
    public function columnNames(): array
    {
        return \array_values(\array_filter([$this->typeColumn, $this->idColumn], static fn (?string $column): bool => $column !== null));
    }

    /**
     * Return the tenant of the model's record, read raw, or null when it has
     * none.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function tenantOf(Model $model): ?Reference
    {
        if ($this->idColumn === null) {
            return null;
        }

        $attributes = $model->getAttributes();
        $id         = self::rawOf($attributes, $this->idColumn);
        $type       = $this->typeColumn === null ? $this->type : self::rawOf($attributes, $this->typeColumn);

        return $id === null || $type === null ? null : new Reference((string) $type, (string) $id);
    }

    /**
     * Return a column's raw value: a string, an integer or null.
     *
     * @param  array<string, mixed>  $attributes
     * @param  string  $column
     * @return int|string|null
     *
     * @throws \UnexpectedValueException
     */
    private static function rawOf(array $attributes, string $column): int|string|null
    {
        if (!\array_key_exists($column, $attributes)) {
            throw new \UnexpectedValueException("The tenant column '{$column}' was not loaded, so the record's tenant cannot be read.");
        }

        $value = $attributes[$column];

        if ($value !== null && !\is_int($value) && !\is_string($value)) {
            throw new \UnexpectedValueException("The tenant column '{$column}' holds neither a string nor an integer.");
        }

        return $value;
    }

    /**
     * Return the column name, refusing an empty one.
     *
     * @param  string  $column
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function column(string $column): string
    {
        if ($column === '') {
            throw new \InvalidArgumentException('A tenant column has a name.');
        }

        return $column;
    }
}
