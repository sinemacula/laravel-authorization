<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

/**
 * The names of the permissions a set of roles carries, and the seconds until
 * the nearest of those grants expires, so a resolution built from them is
 * cached no longer than it holds, and, read for grant usage tracking, which
 * role carries which permission.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class InheritedPermissions
{
    /**
     * Create a new set of inherited permissions.
     *
     * @param  list<string>  $names
     * @param  int|null  $expiresIn
     * @param  array<string, list<array{id: string, name: string}>>|null  $byRole
     */
    public function __construct(

        /** The names of the permissions, each once. */
        public array $names,

        /** The seconds until the nearest grant expires; null when none does. */
        public ?int $expiresIn,

        /** Each permission's key and name, by the key of each role carrying it; null when not read. */
        public ?array $byRole = null,
    ) {}
}
