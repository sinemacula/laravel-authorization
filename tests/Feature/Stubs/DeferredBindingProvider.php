<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Support\ServiceProvider;

/**
 * A sibling package's deferred service provider, which binds each contract it
 * provides to the object a test gives it only once the contract is first
 * resolved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DeferredBindingProvider extends ServiceProvider implements DeferrableProvider
{
    /** @var array<class-string, object> The object each contract the provider provides is bound to. */
    public static array $objects = [];

    /**
     * Bind each contract to its object.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        foreach (self::$objects as $contract => $bound) {
            $this->app->bind($contract, static fn (): object => $bound);
        }
    }

    /**
     * Return the contracts the provider binds.
     *
     * @return list<class-string>
     */
    #[\Override]
    public function provides(): array
    {
        return \array_keys(self::$objects);
    }
}
