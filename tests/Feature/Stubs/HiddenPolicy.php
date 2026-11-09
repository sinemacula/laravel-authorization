<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * A policy model whose global scope hides every policy named `hidden`, so a
 * policy its holder reaches through a role, whose attachment is read without
 * the model's scopes, finds no row once it is hydrated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HiddenPolicy extends Policy
{
    /**
     * Hide every policy named `hidden`.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        parent::booted();

        self::addGlobalScope('visible', static fn (Builder $query): Builder => $query->where('name', '!=', 'hidden'));
    }
}
