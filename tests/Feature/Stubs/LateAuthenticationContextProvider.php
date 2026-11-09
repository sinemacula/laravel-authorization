<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;

/**
 * A sibling package's service provider that registers after the authorization
 * package and binds its own authentication context, contributing `mfa` and
 * `sso` and declaring the assurance key names it is given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LateAuthenticationContextProvider extends ServiceProvider
{
    /**
     * Create a new provider binding a context that declares the names given.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  array<array-key, mixed>  $assuranceKeys
     */
    public function __construct(

        // The application the context is bound in.
        Application $app,

        /** The assurance key names the bound context declares. */
        private readonly array $assuranceKeys = [],
    ) {
        parent::__construct($app);
    }

    /**
     * Bind the authentication context.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->instance(AuthenticationContext::class, new ContributingAuthenticationContext(['mfa', 'sso'], $this->assuranceKeys));
    }
}
