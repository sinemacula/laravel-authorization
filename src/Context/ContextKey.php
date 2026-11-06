<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use SineMacula\Laravel\Authorization\Enums\ContextKeyType;

/**
 * A declared context key: its full dot path, its type and whether a condition
 * may test it (N25).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ContextKey
{
    /**
     * Create a new context key.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\Authorization\Enums\ContextKeyType  $type
     * @param  bool  $isTestable
     */
    public function __construct(

        /** The key's full dot path, its namespace first, such as `request.ip`. */
        public string $path,

        /** The key's type, which decides the operators a condition may test it with. */
        public ContextKeyType $type,

        /** Whether a condition may test the key; an informational key can only be read. */
        public bool $isTestable = true,
    ) {}

    /**
     * Return the namespace the key belongs to: its first segment.
     *
     * @return string
     */
    public function namespace(): string
    {
        return \explode('.', $this->path, 2)[0];
    }
}
