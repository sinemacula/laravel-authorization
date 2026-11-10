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
}
