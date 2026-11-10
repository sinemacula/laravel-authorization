<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Enums;

/**
 * How long what a binding builds lives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Lifetime: string
{
    /** Built afresh each time it is resolved (`bind()`). */
    case TRANSIENT = 'transient';

    /** Built once for as long as the application runs (`singleton()`). */
    case SINGLETON = 'singleton';

    /** Built once per request or job (`scoped()`). */
    case SCOPED = 'scoped';

    /** An object handed to the container (`instance()`). */
    case INSTANCE = 'instance';

    /**
     * Determine whether what lives this long outlives what lives as long as the
     * other: an instance outlives a singleton, which outlives what is scoped,
     * which outlives what is built afresh each time.
     *
     * A binding forwarding to another key builds what lives as long as the
     * longer of the two, as whichever keeps what it built hands it back.
     *
     * @param  self  $other
     * @return bool
     */
    public function outlives(self $other): bool
    {
        return match ($this) {
            self::TRANSIENT => false,
            self::SCOPED    => $other === self::TRANSIENT,
            self::SINGLETON => $other === self::TRANSIENT || $other === self::SCOPED,
            self::INSTANCE  => $other !== self::INSTANCE,
        };
    }
}
