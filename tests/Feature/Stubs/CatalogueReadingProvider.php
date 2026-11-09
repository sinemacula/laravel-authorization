<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;

/**
 * A sibling package's service provider that resolves the context key catalogue
 * while providers register, before the provider binding the authentication
 * context has registered, and declares on it the keys it is given again as
 * untestable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CatalogueReadingProvider extends ServiceProvider
{
    /**
     * Create a new provider declaring the keys given again as untestable.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType>  $untestable
     */
    public function __construct(

        // The application the catalogue is resolved from.
        Application $app,

        /** The keys declared again as untestable, by dot path, with their types. */
        private readonly array $untestable = [],
    ) {
        parent::__construct($app);
    }

    /**
     * Resolve the context key catalogue, declare a key on it, and declare the
     * keys given again as untestable.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue $catalogue */
        $catalogue = $this->app->make(ContextKeyCatalogue::class);

        $catalogue->register('mfa', ['enrolled' => 'bool']);

        foreach ($this->untestable as $path => $type) {
            $catalogue->declare($path, $type, false);
        }
    }
}
