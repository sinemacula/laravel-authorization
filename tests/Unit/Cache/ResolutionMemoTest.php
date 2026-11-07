<?php

declare(strict_types = 1);

namespace Tests\Unit\Cache;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Cache\ResolutionMemo;
use Tests\Fixtures\ScopeKeyHolder;

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

    /**
     * Without a batch, a change of scope drops every entry, whether or not the
     * memo can tell scopes apart.
     *
     * @return void
     */
    public function testAChangeOfScopeOutsideABatchDropsTheEntries(): void
    {
        foreach ([new ResolutionMemo, new ResolutionMemo(static fn (): string => 'tenant-a')] as $memo) {
            $memo->put(self::KEY, ['editor'], null);
            $memo->scopeChanged();

            self::assertNull($memo->get(self::KEY));
        }
    }

    /**
     * A callback run aside, in another scope, gets back what it returns, and
     * the entries of the scope it is run from are put back once it returns,
     * however it ends; a flush within it drops them for good, while one before
     * it does not stop them being put back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEntriesSetAsideArePutBackUnlessAFlushDropsThem(): void
    {
        $memo = new ResolutionMemo;

        $memo->put(self::KEY, ['stale'], null);
        $memo->flush();
        $memo->put(self::KEY, ['editor'], null);

        $result = $memo->aside(static function () use ($memo): string {
            $memo->scopeChanged();
            $memo->put(self::KEY, ['viewer'], null);
            $memo->scopeChanged();

            return 'listed';
        });

        self::assertSame('listed', $result);
        self::assertSame(['editor'], $memo->get(self::KEY));

        try {
            $memo->aside(static function () use ($memo): never {
                $memo->scopeChanged();

                throw new \RuntimeException('failed');
            });
        } catch (\RuntimeException) {
            // The entries are put back however the callback ends.
        }

        self::assertSame(['editor'], $memo->get(self::KEY));

        $memo->aside(static function () use ($memo): void {
            $memo->flush();
            $memo->put(self::KEY, ['viewer'], null);
        });

        self::assertSame(['viewer'], $memo->get(self::KEY));
    }

    /**
     * Within a batch, the entries set aside are put back as the current
     * scope's, taken under its key, so the batch closing keeps them and a later
     * change of scope sets them aside under that key.
     *
     * @return void
     */
    public function testEntriesSetAsideInABatchArePutBackAsTheCurrentScopes(): void
    {
        $scope = new ScopeKeyHolder;
        $memo  = new ResolutionMemo(static fn (): string => $scope->key);

        $memo->open();
        $memo->put(self::KEY, ['editor'], null);

        $memo->aside(static function () use ($memo, $scope): void {
            $scope->key = 'tenant-b';
            $memo->scopeChanged();
            $memo->put(self::KEY, ['viewer'], null);
            $scope->key = 'tenant-a';
            $memo->scopeChanged();
        });

        $scope->key = 'tenant-b';
        $memo->scopeChanged();

        self::assertSame(['viewer'], $memo->get(self::KEY));

        $scope->key = 'tenant-a';
        $memo->scopeChanged();

        self::assertSame(['editor'], $memo->get(self::KEY));

        $memo->aside(static function () use ($memo, $scope): void {
            $scope->key = 'tenant-b';
            $memo->scopeChanged();
            $scope->key = 'tenant-a';
            $memo->scopeChanged();
        });

        $memo->close();

        self::assertSame(['editor'], $memo->get(self::KEY));
    }

    /**
     * Within a batch, each scope keeps its own entries: those of the scope left
     * are set aside and taken back when the scope is read again, and the scope
     * entered starts with its own, not the one left's.
     *
     * @return void
     */
    public function testABatchKeepsEachScopesEntriesApart(): void
    {
        $scope = new ScopeKeyHolder;
        $memo  = new ResolutionMemo(static fn (): string => $scope->key);

        $memo->open();
        $memo->put(self::KEY, ['editor'], null);

        $scope->key = 'tenant-b';
        $memo->scopeChanged();

        self::assertNull($memo->get(self::KEY));

        $memo->put(self::KEY, ['viewer'], null);

        $scope->key = 'tenant-a';
        $memo->scopeChanged();

        self::assertSame(['editor'], $memo->get(self::KEY));

        $scope->key = 'tenant-b';
        $memo->scopeChanged();

        self::assertFalse($memo->lapsed(self::KEY));
        self::assertSame(['viewer'], $memo->get(self::KEY));

        $memo->close();
    }

    /**
     * The entries held when a batch opens are the current scope's, kept apart
     * under it once they are first read; entries held when the scope changes
     * before any read are dropped, since the scope they hold in is not known.
     *
     * @return void
     */
    public function testABatchClaimsTheEntriesItOpensWithOnlyOnceRead(): void
    {
        $scope = new ScopeKeyHolder;
        $key   = static fn (): string => $scope->key;

        $claimed = new ResolutionMemo($key);
        $claimed->put(self::KEY, ['editor'], null);
        $claimed->open();

        self::assertSame(['editor'], $claimed->get(self::KEY));

        $scope->key = 'tenant-b';
        $claimed->scopeChanged();
        $scope->key = 'tenant-a';
        $claimed->scopeChanged();

        self::assertSame(['editor'], $claimed->get(self::KEY));

        $unread = new ResolutionMemo($key);
        $unread->put(self::KEY, ['editor'], null);
        $unread->open();
        $unread->scopeChanged();

        self::assertNull($unread->get(self::KEY));
    }

    /**
     * A flush within a batch drops the entries of every scope, those set aside
     * included.
     *
     * @return void
     */
    public function testAFlushWithinABatchDropsEveryScope(): void
    {
        $scope = new ScopeKeyHolder;
        $memo  = new ResolutionMemo(static fn (): string => $scope->key);

        $memo->open();
        $memo->put(self::KEY, ['editor'], null);

        $scope->key = 'tenant-b';
        $memo->scopeChanged();
        $memo->put(self::KEY, ['viewer'], null);
        $memo->flush();

        self::assertNull($memo->get(self::KEY));

        $scope->key = 'tenant-a';
        $memo->scopeChanged();

        self::assertNull($memo->get(self::KEY));
    }

    /**
     * Without a way to tell scopes apart, a batch drops the entries on every
     * change of scope, as no batch does.
     *
     * @return void
     */
    public function testABatchWithoutScopeKeysDropsTheEntriesOnAChange(): void
    {
        $memo = new ResolutionMemo;

        $memo->open();
        $memo->put(self::KEY, ['editor'], null);
        $memo->scopeChanged();

        self::assertNull($memo->get(self::KEY));

        $memo->put(self::KEY, ['viewer'], null);
        $memo->scopeChanged();
        $memo->close();

        self::assertNull($memo->get(self::KEY));
    }

    /**
     * Once the outermost batch closes, the entries set aside are dropped, and
     * the current ones too when the scope changed since they were taken; a
     * nested batch closing changes nothing.
     *
     * @return void
     */
    public function testClosingTheOutermostBatchDropsWhatWasSetAside(): void
    {
        $scope = new ScopeKeyHolder;
        $memo  = new ResolutionMemo(static fn (): string => $scope->key);

        $memo->open();
        $memo->open();
        $memo->put(self::KEY, ['editor'], null);

        $scope->key = 'tenant-b';
        $memo->scopeChanged();
        $memo->put('other', ['viewer'], null);
        $memo->close();

        $scope->key = 'tenant-a';
        $memo->scopeChanged();

        self::assertSame(['editor'], $memo->get(self::KEY));

        $memo->close();

        $scope->key = 'tenant-b';
        $memo->scopeChanged();

        self::assertNull($memo->get('other'));

        $memo->put('other', ['viewer'], null);
        $memo->open();
        $memo->forget(self::KEY);
        $memo->close();

        self::assertSame(['viewer'], $memo->get('other'));

        $memo->open();
        $memo->get('other');
        $memo->scopeChanged();
        $memo->close();
        $memo->close();

        self::assertNull($memo->get('other'));

        $memo->put('other', ['viewer'], null);
        $memo->scopeChanged();

        self::assertNull($memo->get('other'));
    }

    /**
     * A read of the memo made while the scope's key is read uses the entries as
     * they are, rather than reading the key again.
     *
     * @return void
     */
    public function testAReadWhileTheScopeKeyIsReadUsesTheEntriesAsTheyAre(): void
    {
        $memo  = null;
        $reads = 0;
        $seen  = [];
        $memo  = new ResolutionMemo(static function () use (&$memo, &$reads, &$seen): string {
            $reads++;
            $seen[] = $memo?->get(self::KEY);

            return 'tenant-a';
        });

        $memo->put(self::KEY, ['editor'], null);
        $memo->open();

        self::assertSame(['editor'], $memo->get(self::KEY));
        self::assertSame(1, $reads);
        self::assertSame([['editor']], $seen);

        $memo->close();
    }

    /**
     * Within a batch, an entry whose lifetime ran out while another scope was
     * current has lapsed, as the first read once its scope is entered again.
     *
     * @return void
     */
    public function testAnEntryLapsedInAnotherScopeHasLapsedOnReturn(): void
    {
        $scope = new ScopeKeyHolder;
        $memo  = new ResolutionMemo(static fn (): string => $scope->key);

        $memo->open();
        $memo->put(self::KEY, ['editor'], 1);

        $scope->key = 'tenant-b';
        $memo->scopeChanged();
        $memo->get('other');

        $scope->key = 'tenant-a';
        $memo->scopeChanged();

        Carbon::setTestNow(Carbon::now()->addSeconds(5));

        self::assertTrue($memo->lapsed(self::KEY));

        $memo->close();
    }

    /**
     * Within a batch, forgetting a key as the first read once its scope is
     * entered again forgets the entry of that scope.
     *
     * @return void
     */
    public function testForgettingOnReturnToAScopeForgetsItsEntry(): void
    {
        $scope = new ScopeKeyHolder;
        $memo  = new ResolutionMemo(static fn (): string => $scope->key);

        $memo->open();
        $memo->put(self::KEY, ['editor'], null);

        $scope->key = 'tenant-b';
        $memo->scopeChanged();
        $memo->get('other');

        $scope->key = 'tenant-a';
        $memo->scopeChanged();
        $memo->forget(self::KEY);

        self::assertNull($memo->get(self::KEY));

        $memo->close();
    }

    /**
     * Closing a batch that is not open leaves no batch open below zero: one
     * opened after it still keeps each scope's entries apart, and nested
     * batches close only with the outermost.
     *
     * @return void
     */
    public function testClosingWithNoBatchOpenLeavesTheNextBatchWhole(): void
    {
        $scope = new ScopeKeyHolder;
        $memo  = new ResolutionMemo(static fn (): string => $scope->key);

        $memo->close();
        $memo->open();
        $memo->put(self::KEY, ['editor'], null);

        $scope->key = 'tenant-b';
        $memo->scopeChanged();
        $memo->get('other');

        $scope->key = 'tenant-a';
        $memo->scopeChanged();

        self::assertSame(['editor'], $memo->get(self::KEY));

        $memo->open();
        $memo->open();
        $memo->close();
        $memo->close();

        $scope->key = 'tenant-b';
        $memo->scopeChanged();
        $scope->key = 'tenant-a';
        $memo->scopeChanged();

        self::assertSame(['editor'], $memo->get(self::KEY));

        $memo->close();
    }

    /**
     * Within a batch, the tenant tree is asked each question once, in every
     * scope, unless it is asked afresh, which replaces the answer kept; a
     * question that throws keeps nothing; and with no batch open the tree is
     * asked every time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTreesAnswersAreKeptForTheBatch(): void
    {
        $scope = new ScopeKeyHolder;
        $memo  = new ResolutionMemo(static fn (): string => $scope->key);
        $asked = 0;
        $read  = static function () use (&$asked): int {
            return ++$asked;
        };

        self::assertSame([1, 2], [$memo->tree(['q'], $read), $memo->tree(['q'], $read)]);

        $memo->open();

        self::assertSame(3, $memo->tree(['q'], $read));
        self::assertSame(3, $memo->tree(['q'], $read));
        self::assertSame(4, $memo->tree(['q', 'other'], $read));
        self::assertSame(5, $memo->tree(["q\0", 'other'], $read));
        self::assertSame(6, $memo->tree(['q', "\0other"], $read));

        $scope->key = 'tenant-b';
        $memo->scopeChanged();

        self::assertSame(3, $memo->tree(['q'], $read));
        self::assertSame(7, $memo->tree(['q'], $read, true));
        self::assertSame(7, $memo->tree(['q'], $read));

        $failing = static function () use (&$asked): int {
            throw new \RuntimeException('unavailable ' . $asked);
        };

        try {
            $memo->tree(['broken'], $failing);
        } catch (\RuntimeException $exception) {
            self::assertSame('unavailable 7', $exception->getMessage());
        }

        self::assertSame(8, $memo->tree(['broken'], $read));

        $memo->close();

        self::assertSame(9, $memo->tree(['q'], $read));
    }

    /**
     * A flush drops the tree's answers, as closing the outermost batch does, so
     * the tree is asked again.
     *
     * @return void
     */
    public function testAFlushOrTheBatchClosingDropsTheTreesAnswers(): void
    {
        $memo  = new ResolutionMemo(static fn (): string => 'tenant-a');
        $asked = 0;
        $read  = static function () use (&$asked): int {
            return ++$asked;
        };

        $memo->open();
        $memo->tree(['q'], $read);
        $memo->flush();

        self::assertSame(2, $memo->tree(['q'], $read));

        $memo->close();
        $memo->open();

        self::assertSame(3, $memo->tree(['q'], $read));

        $memo->open();
        $memo->close();

        self::assertSame(3, $memo->tree(['q'], $read));

        $memo->close();
    }
}
