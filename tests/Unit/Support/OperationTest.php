<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `Operation`, one call that changes the package's records.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Operation::class)]
final class OperationTest extends TestCase
{
    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An operation begun with no actor has a new UUID, no actor, and the
     * current time in UTC.
     *
     * @return void
     */
    public function testBeginsWithANewIdAndTheTimeInUtc(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-07-01 14:00:00', 'Europe/Paris'));

        $operation = Operation::begin();

        self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $operation->id);
        self::assertNull($operation->actor);
        self::assertSame('2026-07-01T12:00:00+00:00', $operation->at->format(\DATE_ATOM));
        self::assertSame('UTC', $operation->at->getTimezone()->getName());
    }

    /**
     * Each operation has an id of its own.
     *
     * @return void
     */
    public function testEachOperationHasItsOwnId(): void
    {
        self::assertNotSame(Operation::begin()->id, Operation::begin()->id);
    }

    /**
     * The actor is named by a reference, whether the caller passed a model or a
     * reference.
     *
     * @return void
     */
    public function testNamesTheActorByReference(): void
    {
        $reference = new Reference('user', '7');
        $model     = new class extends Model {};

        $model->forceFill(['id' => 42]);

        self::assertSame($reference, Operation::begin($reference)->actor);
        self::assertEquals(new Reference($model->getMorphClass(), '42'), Operation::begin($model)->actor);
    }
}
