<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

/**
 * What one resolved resource pattern matches among the records of a type, as
 * `Statement::covers()` matches it against each record's identifier: every
 * record, none, the record whose key is exactly a value, or every record whose
 * key starts with a value, byte for byte, the key exactly the value left out
 * when the value ends in `:*` or is `*`, since `covers()` then also needs the
 * identifier less its last byte to match.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyTarget
{
    /** @var string Every record of the type. */
    public const string ALL = 'all';

    /** @var string No record of the type. */
    public const string NONE = 'none';

    /** @var string The record whose key is exactly the value. */
    public const string EQUALS = 'equals';

    /** @var string Every record whose key starts with the value. */
    public const string PREFIX = 'prefix';

    /**
     * Create a new key target.
     *
     * @param  string  $kind
     * @param  string  $value
     * @param  bool  $isValueExcluded
     */
    private function __construct(

        /** Which records it matches: one of the constants. */
        public string $kind,

        /** The key, or the start of the key, it matches; empty for every record or none. */
        public string $value = '',

        /** Whether a key exactly the value is left out of a prefix's records. */
        public bool $isValueExcluded = false,
    ) {}

    /**
     * Return the target of every record.
     *
     * @return self
     */
    public static function all(): self
    {
        return new self(self::ALL);
    }

    /**
     * Return the target of no record.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self(self::NONE);
    }

    /**
     * Return the target of the record whose key is exactly the value.
     *
     * @param  string  $key
     * @return self
     */
    public static function equals(string $key): self
    {
        return new self(self::EQUALS, $key);
    }

    /**
     * Return the target of every record whose key starts with the value, a key
     * exactly the value left out when asked.
     *
     * @param  string  $start
     * @param  bool  $isValueExcluded
     * @return self
     */
    public static function prefix(string $start, bool $isValueExcluded): self
    {
        return new self(self::PREFIX, $start, $isValueExcluded);
    }

    /**
     * Determine whether the target matches every record, whatever its key.
     *
     * @return bool
     */
    public function isAll(): bool
    {
        return $this->kind === self::ALL;
    }

    /**
     * Determine whether the target matches no record.
     *
     * @return bool
     */
    public function isNone(): bool
    {
        return $this->kind === self::NONE;
    }
}
