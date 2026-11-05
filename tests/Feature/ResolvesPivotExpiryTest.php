<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\ResolvesPivotExpiry;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the grant service accessor `ResolvesPivotExpiry` gives the
 * identity traits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ResolvesPivotExpiry::class)]
final class ResolvesPivotExpiryTest extends TestCase
{
    /**
     * The identity traits write through the grant service the container binds.
     *
     * @return void
     */
    public function testWritesThroughTheBoundGrantService(): void
    {
        $role = Role::query()->create(['name' => 'editor']);

        StubIdentity::query()->create(['id' => 'user-1'])->assignRole($role);

        self::assertSame([$role->id], DB::table('authorizable_roles')->pluck('role_id')->all());
    }

    /**
     * Without the grant service bound, a write is refused rather than lost.
     *
     * @return void
     */
    public function testRefusesAWriteWithoutTheGrantService(): void
    {
        $user = StubIdentity::query()->create(['id' => 'user-1']);

        unset($this->app[GrantService::class]);

        $this->expectExceptionObject(new \LogicException('The authorization grant service is not bound; register the package\'s service provider.'));

        $user->assignRole('editor');
    }
}
