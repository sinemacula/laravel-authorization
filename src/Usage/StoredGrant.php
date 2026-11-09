<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The stored grant a route starts from, as grant usage tracking records it (see
 * `GrantRoute`): the table it is stored in, the key of the role, permission or
 * policy it grants, its grantee, its tenant and application as stored, and when
 * it was created, in UTC.
 *
 * Its columns are those that make the row unique, so the usage pruner can tell
 * whether it still exists, and its creation tells a regrant apart from the
 * grant it replaced: a revoked grant made again is a new row, created later,
 * which never inherits the use of the old one.
 *
 * @phpstan-type StoredGrantArray array{
 *     grant_source: string,
 *     grant_id: string,
 *     authorizable_type: string,
 *     authorizable_id: string,
 *     tenant_type: string|null,
 *     tenant_id: string|null,
 *     application: string|null,
 *     grant_created_at: int|null
 * }
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StoredGrant
{
    /**
     * Create a new stored grant.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $source
     * @param  string  $grantId
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  string|null  $tenantType
     * @param  string|null  $tenantId
     * @param  string|null  $application
     * @param  int|null  $createdAt
     */
    public function __construct(

        /** The kind of grant, which names the table the row is stored in. */
        public GrantTarget $source,

        /** The key of the role, permission or policy the row grants. */
        public string $grantId,

        /** Whom the row grants to. */
        public Reference $grantee,

        /** The tenant's morph type, as stored; null for none. */
        public ?string $tenantType,

        /** The tenant's key, as stored; null for none. */
        public ?string $tenantId,

        /** The application, as stored; null for every application. */
        public ?string $application,

        /** When the row was created, as a UTC timestamp; null when it records none. */
        public ?int $createdAt,
    ) {}

    /**
     * Return the stored grant a related model was read through, from the
     * columns of its pivot as they are stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $source
     * @param  \Illuminate\Database\Eloquent\Model  $related
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return self
     */
    public static function throughPivot(GrantTarget $source, Model $related, Reference $grantee): self
    {
        /** @var \Illuminate\Database\Eloquent\Model $pivot */
        $pivot = $related->getRelation('pivot');
        $key   = $related->getKey();

        return self::of($source, \is_scalar($key) ? (string) $key : '', $grantee, $pivot->getAttributes());
    }

    /**
     * Return the stored grant of the key, to the grantee, from the columns of
     * its row as they are stored: its tenant's type and key, its application
     * and its creation, read as a UTC wall-clock time, as an access review
     * reads it.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $source
     * @param  string  $grantId
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<array-key, mixed>  $columns
     * @return self
     */
    public static function of(GrantTarget $source, string $grantId, Reference $grantee, array $columns): self
    {
        $text    = static fn (string $column): ?string => \is_scalar($columns[$column] ?? null) ? (string) $columns[$column] : null;
        $created = UtcDateTime::toUtc($columns['created_at'] ?? null)?->getTimestamp();

        return new self($source, $grantId, $grantee, $text('tenant_type'), $text('tenant_id'), $text('application'), $created);
    }

    /**
     * Return the stored grant as the plain values a cache entry and a usage row
     * hold.
     *
     * @return StoredGrantArray
     */
    public function toArray(): array
    {
        return [
            'grant_source'      => $this->source->value,
            'grant_id'          => $this->grantId,
            'authorizable_type' => $this->grantee->type,
            'authorizable_id'   => $this->grantee->id,
            'tenant_type'       => $this->tenantType,
            'tenant_id'         => $this->tenantId,
            'application'       => $this->application,
            'grant_created_at'  => $this->createdAt,
        ];
    }

    /**
     * Return the stored grant the plain values describe, refusing values that
     * do not have its shape.
     *
     * @param  mixed  $values
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function fromArray(mixed $values): self
    {
        if (!\is_array($values) || !self::hasShape($values)) {
            throw new \UnexpectedValueException('A stored grant is not the shape grant usage tracking keeps.');
        }

        /** @var StoredGrantArray $values */
        $grantee = new Reference($values['authorizable_type'], $values['authorizable_id']);

        return new self(
            GrantTarget::from($values['grant_source']),
            $values['grant_id'],
            $grantee,
            $values['tenant_type'],
            $values['tenant_id'],
            $values['application'],
            $values['grant_created_at'],
        );
    }

    /**
     * Determine whether the values have a stored grant's shape: a known kind, a
     * key and a grantee, each tenant column and the application a string or
     * nothing, and the creation a timestamp or nothing.
     *
     * @param  array<array-key, mixed>  $values
     * @return bool
     */
    private static function hasShape(array $values): bool
    {
        $source  = \is_string($values['grant_source'] ?? null) ? GrantTarget::tryFrom($values['grant_source']) : null;
        $strings = \array_filter([$values['grant_id'] ?? null, $values['authorizable_type'] ?? null, $values['authorizable_id'] ?? null], \is_string(...));
        $created = $values['grant_created_at'] ?? null;

        return $source !== null && \count($strings) === 3 && self::isNullableText($values, ['tenant_type', 'tenant_id', 'application']) && ($created === null || \is_int($created));
    }

    /**
     * Determine whether each of the columns holds a string or nothing.
     *
     * @param  array<array-key, mixed>  $values
     * @param  list<string>  $columns
     * @return bool
     */
    private static function isNullableText(array $values, array $columns): bool
    {
        foreach ($columns as $column) {
            $value = $values[$column] ?? null;

            if ($value !== null && !\is_string($value)) {
                return false;
            }
        }

        return true;
    }
}
