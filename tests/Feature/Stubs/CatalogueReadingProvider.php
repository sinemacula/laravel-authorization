<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;

/**
 * A sibling package's service provider that resolves the context key catalogue
 * while providers register, before the provider binding the authentication
 * context has registered.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CatalogueReadingProvider extends ServiceProvider
{
    /**
     * Resolve the context key catalogue and declare a key on it.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue $catalogue */
        $catalogue = $this->app->make(ContextKeyCatalogue::class);

        $catalogue->register('mfa', ['enrolled' => 'bool']);
    }
}
