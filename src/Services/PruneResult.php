<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

/**
 * What `GrantPruner::prune()` removed, or, pretending, would remove.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PruneResult
{
    /**
     * Create a new prune result.
     *
     * @param  int  $expired
     * @param  int  $orphaned
     * @param  list<string>  $unresolvedTypes
     */
    public function __construct(

        /** The grants removed because they had expired. */
        public int $expired,

        /** The grants removed because their grantee no longer exists. */
        public int $orphaned,

        /** The grantee types that name no model class, whose grants were left. */
        public array $unresolvedTypes,
    ) {}
}
