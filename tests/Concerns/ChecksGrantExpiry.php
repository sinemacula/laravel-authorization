<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use Tests\Feature\Stubs\StubIdentity;

/**
 * Shared checks of a grant's expiry: given in another zone, it is stored in UTC
 * and lapses at the instant it names in an application whose zone is not UTC;
 * changed by a second grant on the package's own connection, the change is
 * reported with the expiry the grant had before.
 *
 * In the zone check the application runs in Tokyo (UTC+9) and the expiry is
 * given in New York (UTC-4 in July): a grant made at 12:00 UTC until 10:00 New
 * York time (14:00 UTC) is stored as 14:00, is still held at 13:00 UTC and has
 * lapsed just after 14:00 UTC.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ChecksGrantExpiry
{
    use UsesAnAuthorizationConnection;

    /**
     * A second grant on the configured connection reads the first grant there,
     * so the change of expiry is reported with the expiry it replaced.
     *
     * @return void
     */
    public function testRegrantOnTheConfiguredConnectionReportsThePriorExpiry(): void
    {
        $this->useAnAuthorizationConnection();

        $first    = Carbon::parse('2030-01-01 12:00:00', 'UTC');
        $second   = Carbon::parse('2030-06-01 12:00:00', 'UTC');
        $identity = StubIdentity::create(['id' => (string) Str::uuid()]);

        $this->grantUntil($identity, $first);

        Event::fake([static::expiryChangedEvent()]);

        $this->grantUntil($identity, $second);

        Event::assertDispatched(static::expiryChangedEvent(), static fn (object $event): bool => \property_exists($event, 'previousExpiresAt')
            && \property_exists($event, 'expiresAt')
            && $event->previousExpiresAt instanceof \DateTimeInterface
            && $event->expiresAt instanceof \DateTimeInterface
            && $event->previousExpiresAt->getTimestamp() === $first->getTimestamp()
            && $event->expiresAt->getTimestamp()         === $second->getTimestamp());
        self::assertSame(1, self::authorizationConnection()->table(static::grantTable())->count());
        self::assertSame(0, DB::table(static::grantTable())->count());
    }

    /**
     * An expiry given in another zone is stored in UTC and lapses at the
     * instant it names.
     *
     * @return void
     */
    public function testExpiryInAnotherZoneLapsesAtItsInstant(): void
    {
        $zone = \date_default_timezone_get();

        \date_default_timezone_set('Asia/Tokyo');

        try {
            Carbon::setTestNow(Carbon::parse('2026-07-01 12:00:00', 'UTC'));

            $identity = StubIdentity::create(['id' => (string) Str::uuid()]);

            $this->grantUntil($identity, Carbon::parse('2026-07-01 10:00:00', 'America/New_York'));

            /** @var string $stored */
            $stored = DB::table(static::grantTable())->value('expires_at');

            self::assertSame('2026-07-01 14:00:00', Carbon::parse($stored)->format('Y-m-d H:i:s'));

            Carbon::setTestNow(Carbon::parse('2026-07-01 13:00:00', 'UTC'));

            self::assertSame([static::grantedName()], $this->heldNames(self::reload($identity)));

            Carbon::setTestNow(Carbon::parse('2026-07-01 14:00:01', 'UTC'));

            self::assertSame([], $this->heldNames(self::reload($identity)));
        } finally {
            \date_default_timezone_set($zone);
            Carbon::setTestNow();
        }
    }

    /**
     * Return the grant table the check reads.
     *
     * @return string
     */
    abstract protected static function grantTable(): string;

    /**
     * Return the event a change of the grant's expiry dispatches.
     *
     * @return class-string
     */
    abstract protected static function expiryChangedEvent(): string;

    /**
     * Return the name of the row the check grants.
     *
     * @return string
     */
    abstract protected static function grantedName(): string;

    /**
     * Grant the identity the row named by `grantedName()` until the given
     * instant, creating the row on the first grant.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \DateTimeInterface  $expiresAt
     * @return void
     */
    abstract protected function grantUntil(StubIdentity $identity, \DateTimeInterface $expiresAt): void;

    /**
     * Return the names of the rows the identity holds through the grant
     * relation.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @return list<string>
     */
    abstract protected function heldNames(StubIdentity $identity): array;

    /**
     * Load the identity afresh, so its relations are read again.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function reload(Model $identity): StubIdentity
    {
        /** @var \Tests\Feature\Stubs\StubIdentity */
        return StubIdentity::query()->findOrFail($identity->getKey());
    }
}
