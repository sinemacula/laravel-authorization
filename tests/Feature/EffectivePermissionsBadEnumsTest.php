<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests covering the `effectivePermissions()` filter branch
 * that rejects non-string or non-enum entries from the configured
 * `authorization.permission_enums` list. Guards the manager against
 * misconfigured arrays — booleans, integers, string class-names that
 * are not enums — without letting the call blow up at runtime.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationManager::class)]
final class EffectivePermissionsBadEnumsTest extends TestCase
{
    /**
     * Non-string and non-enum entries in the configured list are
     * silently skipped so misconfiguration can never cascade into a
     * TypeError mid-request.
     *
     * @return void
     */
    public function testNonStringAndNonEnumEntriesAreSkipped(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [
            123,                             // non-string
            \stdClass::class,                // string but not a PermissionEnum subclass
            ['nested'],                      // non-scalar
            null,                            // null entry
        ]);

        $user = StubIdentity::create(['id' => 'ff985fd2-2a0a-4a27-82bd-dcd3ce983740']);

        $effective = Authorization::for($user)->effectivePermissions();

        self::assertSame([], $effective);
    }
}
