<?php

declare(strict_types = 1);

namespace Tests\Unit\Cache;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Cache\ResolutionMemo;

/**
 * Unit tests for `ResolutionMemo`, the in-memory tier of the resolution cache,
 * whose entries lapse with the lifetime they were stored with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolutionMemo::class)]
final class ResolutionMemoTest extends TestCase
{
    /** @var string Key every test stores under. */
    private const string KEY = 'authorization:roles:principal';

    /**
     * Start every test at a fixed instant.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-01 12:00:00');
    }

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A key that was never stored has no entry.
     *
     * @return void
     */
    public function testMissingKeyHasNoEntry(): void
    {
        self::assertNull((new ResolutionMemo)->get(self::KEY));
    }

    /**
     * An entry with a lifetime is served until that many seconds have passed,
     * and not from then on.
     *
     * @return void
     */
    public function testEntryLapsesAtTheEndOfItsLifetime(): void
    {
        $memo = new ResolutionMemo;
        $memo->put(self::KEY, ['editor'], 30);

        Carbon::setTestNow('2026-07-01 12:00:29');

        self::assertSame(['editor'], $memo->get(self::KEY));

        Carbon::setTestNow('2026-07-01 12:00:30');

        self::assertNull($memo->get(self::KEY));
    }

    /**
     * An entry stored without a lifetime does not lapse.
     *
     * @return void
     */
    public function testEntryWithoutLifetimeDoesNotLapse(): void
    {
        $memo = new ResolutionMemo;
        $memo->put(self::KEY, ['editor'], null);

        Carbon::setTestNow('2036-07-01 12:00:00');

        self::assertSame(['editor'], $memo->get(self::KEY));
    }

    /**
     * An entry stored with no lifetime left has already lapsed.
     *
     * @return void
     */
    public function testEntryWithoutLifetimeLeftHasLapsed(): void
    {
        $memo = new ResolutionMemo;
        $memo->put(self::KEY, ['editor'], 0);

        self::assertNull($memo->get(self::KEY));
    }

    /**
     * Storing again replaces the entry and its lifetime.
     *
     * @return void
     */
    public function testPutReplacesTheEntry(): void
    {
        $memo = new ResolutionMemo;
        $memo->put(self::KEY, ['editor'], 0);
        $memo->put(self::KEY, ['viewer'], 10);

        self::assertSame(['viewer'], $memo->get(self::KEY));
    }

    /**
     * Only an entry whose lifetime has run out has lapsed: a missing key, a
     * live entry and an entry stored forever have not.
     *
     * @return void
     */
    public function testOnlyAnEntryPastItsLifetimeHasLapsed(): void
    {
        $memo = new ResolutionMemo;
        $memo->put(self::KEY, ['editor'], 30);
        $memo->put('forever', ['viewer'], null);

        self::assertFalse($memo->lapsed('missing'));

        Carbon::setTestNow('2026-07-01 12:00:29');

        self::assertFalse($memo->lapsed(self::KEY));

        Carbon::setTestNow('2026-07-01 12:00:30');

        self::assertTrue($memo->lapsed(self::KEY));

        Carbon::setTestNow('2036-07-01 12:00:00');

        self::assertFalse($memo->lapsed('forever'));
        self::assertSame(['viewer'], $memo->get('forever'));
    }

    /**
     * `forget()` drops one entry and `flush()` drops every entry.
     *
     * @return void
     */
    public function testForgetAndFlushDropEntries(): void
    {
        $memo = new ResolutionMemo;
        $memo->put(self::KEY, ['editor'], null);
        $memo->put('other', ['viewer'], null);

        $memo->forget(self::KEY);

        self::assertNull($memo->get(self::KEY));
        self::assertSame(['viewer'], $memo->get('other'));

        $memo->flush();

        self::assertNull($memo->get('other'));
    }
}
