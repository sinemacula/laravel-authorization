<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;

/**
 * A record named by its morph type and key: a grantee, a granted role,
 * permission or policy, an actor, or a tenant.
 *
 * The type is the model's morph class under the application's morph map, never
 * a hard-coded class name, and the key a string, so references from every
 * member of the suite match. Both are bounded to 191 bytes, as the grant tables
 * store them; a longer one is refused.
 *
 * It answers `getMorphClass()` and `getKey()` as a model does, so the grant
 * service and the resolution cache treat it as the record it names, including a
 * grantee that is not loaded, or whose model class is not available, such as
 * the rows an import copies from another package's tables. A reference carries
 * no guard, so a role or permission named by a string is looked up under the
 * package's default guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Reference implements AuthorizableTenant
{
    /** @var int The most bytes a reference's type or key may hold. */
    public const int MAX_BYTES = 191;

    /**
     * Create a new reference.
     *
     * @param  string  $type
     * @param  string  $id
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The record's morph type, as `authorizable_type` stores it. */
        public string $type,

        /** The record's key, as `authorizable_id` stores it. */
        public string $id,
    ) {
        if (\strlen($type) > self::MAX_BYTES || \strlen($id) > self::MAX_BYTES) {
            throw new \InvalidArgumentException('A reference\'s type and key are at most ' . self::MAX_BYTES . ' bytes each.');
        }
    }

    /**
     * Return the reference to a model, by its morph class and key, or the
     * reference itself.
     *
     * @param  \Illuminate\Database\Eloquent\Model|self  $record
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(Model|self $record): self
    {
        if ($record instanceof self) {
            return $record;
        }

        $key = $record->getKey();

        return new self($record->getMorphClass(), \is_scalar($key) ? (string) $key : '');
    }

    /**
     * Return the reference to the tenant that owns a role, permission or
     * policy, read from its `tenant_type` and `tenant_id` columns, or null for
     * a record the platform owns.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @return self|null
     *
     * @throws \InvalidArgumentException
     */
    public static function tenantOf(Model $record): ?self
    {
        $type = $record->getAttribute('tenant_type');
        $id   = $record->getAttribute('tenant_id');

        if (!\is_string($type) || !\is_scalar($id)) {
            return null;
        }

        return new self($type, (string) $id);
    }

    /**
     * Return the record's morph type.
     *
     * @return string
     */
    #[\Override]
    public function getMorphClass(): string
    {
        return $this->type;
    }

    /**
     * Return the record's key.
     *
     * @return string
     */
    #[\Override]
    public function getKey(): string
    {
        return $this->id;
    }
}
