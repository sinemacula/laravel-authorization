<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Enums;

/**
 * How an access review selects the stored grants it reads (see
 * `Reviews\ReviewScope`): by what reaches an evaluation scope, by where the
 * grants originate, or everywhere.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ScopeSelection: string
{
    /** The grants that apply in a tenant, or at the platform: what a check there reads. */
    case APPLIES_IN = 'applies_in';

    /** The grants rooted at a tenant or below it in the tenant tree. */
    case ROOTED_WITHIN = 'rooted_within';

    /** Every stored grant, in every tenant and at the platform. */
    case EVERYWHERE = 'everywhere';
}
