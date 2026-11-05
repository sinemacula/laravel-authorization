<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

/**
 * One permission the application declares in code.
 *
 * A definition is one row of the platform's permission catalogue: a name, the
 * guard it applies to (null for guard-agnostic), and the description and
 * category `authorization:sync` writes to the row. Permission providers return
 * definitions, and the sync builds one for each enum case and guard.
 *
 * Two definitions describe the same row when their name and guard match, which
 * `key()` expresses as one string.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionDefinition
{
    /**
     * Create a new permission definition.
     *
     * @param  string  $name
     * @param  string|null  $description
     * @param  string|null  $category
     * @param  string|null  $guard
     */
    public function __construct(

        /** Permission name, checked against the package's name rules. */
        public string $name,

        /** Human-readable description written to the `description` column. */
        public ?string $description = null,

        /** Grouping key for administration screens, written to `category`. */
        public ?string $category = null,

        /** Guard the permission applies to; null for guard-agnostic. */
        public ?string $guard = null,
    ) {}

    /**
     * Return the key of the row a name and guard identify.
     *
     * A null guard and an empty one give the same key, so a guard-agnostic row
     * matches a guard-agnostic definition whichever the database holds.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @return string
     */
    public static function keyOf(string $name, ?string $guard): string
    {
        return $name . "\0" . $guard;
    }

    /**
     * Return the key of the row this definition describes.
     *
     * @return string
     */
    public function key(): string
    {
        return self::keyOf($this->name, $this->guard);
    }

    /**
     * Determine whether the given description and category are the ones this
     * definition declares.
     *
     * @param  string|null  $description
     * @param  string|null  $category
     * @return bool
     */
    public function hasMetadata(?string $description, ?string $category): bool
    {
        return $this->description === $description && $this->category === $category;
    }
}
