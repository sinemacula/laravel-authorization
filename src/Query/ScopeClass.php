<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * One class of a model's rows, every row of which `check()` decides from the
 * same sources (§5.3): the condition a row of it meets, the tenant its rows are
 * decided as having, whether they stand below that tenant rather than in it,
 * and whether they are admitted from outside the request's scope by a
 * platform-wide grant.
 *
 * - A row of no tenant, or every row of a tenantless model, is decided in the
 *   request's scope: no tenant.
 * - A row within the active tenant's subtree is decided in its own tenant's
 *   scope: the anchor it is, or the nearest anchor above it, standing below it.
 * - A row admitted from outside is decided at platform scope, with the
 *   guardrails and the attached denies of its own tenant chain: those of the
 *   anchor it is, or of the nearest above it, standing below it; or none, when
 *   no anchor is on its chain.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ScopeClass
{
    /**
     * Create a new class of rows.
     *
     * @param  string  $membership
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $isBelow
     * @param  bool  $isAdmitted
     */
    public function __construct(

        /** The condition a row of the class meets. */
        public string $membership,

        /** The tenant its rows are decided as having: their own, or the nearest anchor above them; null for none. */
        public ?Reference $tenant = null,

        /** Whether its rows stand below the tenant rather than in it, so a grant made there counts only when it reaches below. */
        public bool $isBelow = false,

        /** Whether its rows are admitted from outside the request's scope, and decided at platform scope. */
        public bool $isAdmitted = false,
    ) {}
}
