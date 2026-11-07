<?php

declare(strict_types = 1);

namespace Tests\Unit\Administration;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Administration\OperationChange;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `OperationChange`, the grant or removal an operation resource
 * proposes, as values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationChange::class)]
final class OperationChangeTest extends TestCase
{
    /**
     * A change holds its grantee, target, scope and whether it changes nothing
     * as given, and its expiry in UTC; it lasts until its expiry, or forever,
     * as `PHP_INT_MAX`, for none.
     *
     * @return void
     */
    public function testItHoldsTheChangeAndItsLifetime(): void
    {
        $grantee = new Reference('user', '1');
        $target  = new class extends Model {};
        $scope   = new GrantScope(new Reference('tenant', 'a'), 'admin', false);
        $expiry  = Carbon::parse('2026-07-02 14:00:00', 'Europe/Paris');
        $change  = new OperationChange($grantee, $target, $scope, $expiry);

        self::assertSame($grantee, $change->grantee);
        self::assertSame($target, $change->target);
        self::assertSame($scope, $change->scope);
        self::assertFalse($change->isUnchanged);
        self::assertSame('2026-07-02T12:00:00+00:00', $change->expiresAt?->format(\DATE_ATOM));
        self::assertSame($expiry->getTimestamp(), $change->lastsUntil());

        $forever = new OperationChange($grantee, null, GrantScope::platform(), null, true);

        self::assertNull($forever->target);
        self::assertNull($forever->expiresAt);
        self::assertTrue($forever->isUnchanged);
        self::assertSame(\PHP_INT_MAX, $forever->lastsUntil());
    }
}
