<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizableGrantPivot;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePermissionPivot;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePolicyPivot;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizableRolePivot;
use Tests\Concerns\ChecksTheConnectionName;
use Tests\TestCase;

/**
 * Feature tests for the shared grant pivot: the connection it names and the
 * cast on its expiry, for each of the three grant pivots.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizableGrantPivot::class)]
final class AuthorizableGrantPivotTest extends TestCase
{
    use ChecksTheConnectionName;

    /**
     * Every grant pivot names the configured connection.
     *
     * @return void
     */
    public function testEveryGrantPivotNamesTheConfiguredConnection(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(Repository::class);

        $config->set('authorization.connection', 'identity');

        foreach ([new AuthorizableRolePivot, new AuthorizablePermissionPivot, new AuthorizablePolicyPivot] as $pivot) {
            self::assertSame('identity', $pivot->getConnectionName(), $pivot::class);
        }
    }

    /**
     * The stored expiry reads back as a date.
     *
     * @return void
     */
    public function testExpiryReadsBackAsADate(): void
    {
        $pivot = new AuthorizableRolePivot;

        $pivot->setRawAttributes(['expires_at' => '2030-01-02 03:04:05']);

        self::assertInstanceOf(Carbon::class, $pivot->expires_at);
        self::assertSame('2030-01-02 03:04:05', $pivot->expires_at->format('Y-m-d H:i:s'));
    }

    /**
     * Create the pivot whose connection is checked.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    protected static function newConnectionModel(): Model
    {
        return new AuthorizableRolePivot;
    }

    /**
     * Determine whether the class under test is a pivot.
     *
     * @return bool
     */
    #[\Override]
    protected static function isAPivot(): bool
    {
        return true;
    }
}
