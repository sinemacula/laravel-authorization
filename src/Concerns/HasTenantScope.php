<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * Applies `TenantScope` to a model and to every subclass of it.
 *
 * Laravel 12 reads `#[ScopedBy]` from the queried class alone, so a subclass
 * would lose an attribute-registered scope; trait boot methods are inherited.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasTenantScope // @phpstan-ignore trait.unused
{
    /**
     * Register the tenant scope.
     *
     * @return void
     */
    protected static function bootHasTenantScope(): void
    {
        static::addGlobalScope(new TenantScope);
    }
}
