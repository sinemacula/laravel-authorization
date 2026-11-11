<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Enums;

/**
 * How far a route reaches, as its origin scope stores it, kept compact rather
 * than expanded into every tenant it covers (see `Reviews\OriginScope`):
 *
 * - `node`: one tenant, and none below it;
 * - `subtree`: one tenant and every tenant below it, named by its root;
 * - `platform`: every tenant and the platform itself, an explicit record rather
 *   than an empty tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ReachKind: string
{
    /** One tenant alone. */
    case NODE = 'node';

    /** A tenant and every tenant below it. */
    case SUBTREE = 'subtree';

    /** The platform, and so every tenant. */
    case PLATFORM = 'platform';
}
