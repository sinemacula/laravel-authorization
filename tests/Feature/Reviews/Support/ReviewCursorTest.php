<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Carbon\CarbonImmutable;
use Illuminate\Encryption\MissingAppKeyException;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Exceptions\InvalidReviewCursorException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewCursor;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewPosition;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ReviewsAccess;
use Tests\TestCase;

/**
 * Feature tests for the cursors of a paged review: signed with a key derived
 * from the application key, carrying the review's instant and its last row's
 * sort key whatever bytes it holds, and refused, with the one exception, when
 * changed in any part, of another schema version, for another query or
 * reviewer, or of any other shape.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ReviewCursor::class)]
final class ReviewCursorTest extends TestCase
{
    use ReviewsAccess;

    /** @var list<bool|int|string|null> A sort key holding every kind of part, with bytes no JSON string could. */
    private const array KEY = [3, 'type', "\x00\xff/\u{e4}", 'u', 'a ', 0, '', 1, 't', 0, '', false, true, null, 'r'];

    /**
     * A cursor carries the review's instant, to the microsecond, and the sort
     * key, every part as it was, for the query and reviewer it was issued for,
     * and is URL-safe.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACursorCarriesItsPosition(): void
    {
        $cursors = new ReviewCursor('key');
        $query   = self::reviewed();
        $at      = CarbonImmutable::parse('2026-11-08 12:00:00.123456', 'UTC');

        foreach ([null, self::reviewer('reviewer')] as $reviewer) {
            $cursor = $cursors->issue(new ReviewPosition($at, self::KEY), $query, $reviewer);

            self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $cursor);

            $position = $cursors->read($cursor, $query, $reviewer);

            self::assertSame(self::KEY, $position->after);
            self::assertSame('2026-11-08 12:00:00.123456', $position->at->format('Y-m-d H:i:s.u'));
            self::assertSame('UTC', $position->at->getTimezone()->getName());
        }

        $zoned = $cursors->issue(new ReviewPosition(CarbonImmutable::parse('2026-11-08 07:00:00', 'America/New_York'), [0]), $query, null);

        self::assertSame('2026-11-08 12:00:00', $cursors->read($zoned, $query, null)->at->format('Y-m-d H:i:s'));
    }

    /**
     * The application key signs the cursors: one given as base64 or as text
     * works, another key's cursor is refused, and no key refuses to sign.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationKeySignsTheCursors(): void
    {
        $query    = self::reviewed();
        $position = new ReviewPosition(CarbonImmutable::now('UTC'), [0]);

        self::keyCursors();

        $cursor = ReviewCursor::forApplication()->issue($position, $query, null);

        self::assertSame([0], ReviewCursor::forApplication()->read($cursor, $query, null)->after);

        config(['app.key' => 'plain-text-key']);

        $plain = ReviewCursor::forApplication()->issue($position, $query, null);

        self::assertSame([0], ReviewCursor::forApplication()->read($plain, $query, null)->after);
        self::assertRefused(static fn (): mixed => ReviewCursor::forApplication()->read($cursor, $query, null));

        config(['app.key' => 'base64:!!!']);

        self::assertSame([0], ReviewCursor::forApplication()->read(ReviewCursor::forApplication()->issue($position, $query, null), $query, null)->after);

        config(['app.key' => null]);

        $this->expectException(MissingAppKeyException::class);

        ReviewCursor::forApplication();
    }

    /**
     * A cursor changed in its payload or its signature, one of another schema
     * version, and one issued for another query, reviewer or the trusted path
     * are each refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATamperedOrForeignCursorIsRefused(): void
    {
        $cursors  = new ReviewCursor('key');
        $query    = self::reviewed();
        $reviewer = self::reviewer('reviewer');
        $cursor   = $cursors->issue(new ReviewPosition(CarbonImmutable::now('UTC'), self::KEY), $query, $reviewer);

        [$payload, $signature] = \explode('.', $cursor);

        $changed = \rtrim(\strtr(\base64_encode(\str_replace('"v":1', '"v":2', self::decoded($payload))), '+/', '-_'), '=');

        self::assertRefused(static fn (): mixed => $cursors->read($changed . '.' . $signature, $query, $reviewer));
        self::assertRefused(static fn (): mixed => $cursors->read($payload . '.' . \strrev($signature), $query, $reviewer));
        self::assertRefused(static fn (): mixed => $cursors->read($payload . '.' . $signature . 'A', $query, $reviewer));
        self::assertRefused(static fn (): mixed => (new ReviewCursor('key', 2))->read($cursor, $query, $reviewer));
        self::assertRefused(static fn (): mixed => (new ReviewCursor('other'))->read($cursor, $query, $reviewer));
        self::assertRefused(static fn (): mixed => $cursors->read($cursor, $query, null));
        self::assertRefused(static fn (): mixed => $cursors->read($cursor, $query, self::reviewer('another')));
        self::assertRefused(static fn (): mixed => $cursors->read($cursor, $query, $reviewer->impersonatedBy(new Reference('u', 'imp'))));

        $others = [
            ReviewQuery::holders(self::role('other'), ReviewScope::everywhere()),
            ReviewQuery::holdings(new Reference('u', 'a'), ReviewScope::everywhere()),
            ReviewQuery::holdings(new Subject(self::identity('ann'), self::identity('ann-identity')), ReviewScope::everywhere()),
            ReviewQuery::expiring(ReviewScope::everywhere(), CarbonImmutable::parse('2026-01-01'), CarbonImmutable::parse('2026-02-01')),
            ReviewQuery::grantedBy(new Reference('u', 'a'), ReviewScope::appliesIn(self::tenant('t'), ApplicationSelector::named('web'))),
        ];

        foreach ($others as $other) {
            self::assertRefused(static fn (): mixed => $cursors->read($cursor, $other, $reviewer));
        }

        self::assertSame(self::KEY, $cursors->read($cursor, $query->withLimit(1), $reviewer)->after);
    }

    /**
     * Anything that is not a cursor is refused unread: empty, of more or fewer
     * parts, not base64url, or longer than any cursor; and a signed payload of
     * any other shape is refused once read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnythingElseIsRefused(): void
    {
        $cursors = new ReviewCursor('key');
        $query   = self::reviewed();

        foreach (['', '.', 'a', 'a.b.c', 'a+b.c', 'YQ.Y=', \str_repeat('a', 16385)] as $text) {
            self::assertRefused(static fn (): mixed => $cursors->read($text, $query, null));
        }

        $payloads = [
            'not json',
            '[]',
            '{"v":1,"at":"2026-11-08T12:00:00.000000Z"}',
            '{"v":1,"at":"yesterday","after":[0]}',
            '{"v":1,"at":"2026-11-08T12:00:00.000000Z","after":[]}',
            '{"v":1,"at":"2026-11-08T12:00:00.000000Z","after":["YQ"]}',
            '{"v":1,"at":"2026-11-08T12:00:00.000000Z","after":[0,{"a":1}]}',
            '{"v":1,"at":"2026-11-08T12:00:00.000000Z","after":[0,"!!"]}',
            '{"v":1,"at":"2026-11-08T12:00:00.000000Z","after":{"x":0}}',
            '{"v":"1","at":"2026-11-08T12:00:00.000000Z","after":[0]}',
        ];

        foreach ($payloads as $payload) {
            self::assertRefused(static fn (): mixed => $cursors->read(self::signed($cursors, $payload, $query), $query, null), $payload);
        }

        self::assertSame([0, 'a'], $cursors->read(self::signed($cursors, '{"v":1,"at":"2026-11-08T12:00:00.000000Z","after":[0,"YQ=="]}', $query), $query, null)->after);
    }

    /**
     * Return the review the cursors are issued for.
     *
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewQuery
     *
     * @throws \Throwable
     */
    private static function reviewed(): ReviewQuery
    {
        return ReviewQuery::holders(new Reference((new Role)->getMorphClass(), '01a1be88-d4d3-72cc-b9bc-620cc97d4906'), ReviewScope::everywhere());
    }

    /**
     * Return the acting context of a new identity with the id.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Administration\ActingContext
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function reviewer(string $id): ActingContext
    {
        $identity = self::identity($id);

        return ActingContext::for(new Subject($identity, $identity));
    }

    /**
     * Return a cursor of the payload, signed by the codec for the query on the
     * trusted path.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewCursor  $cursors
     * @param  string  $payload
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return string
     */
    private static function signed(ReviewCursor $cursors, string $payload, ReviewQuery $query): string
    {
        $sign = (new \ReflectionMethod($cursors, 'signature'))->getClosure($cursors);

        self::assertInstanceOf(\Closure::class, $sign);

        $encode = static fn (string $bytes): string => \rtrim(\strtr(\base64_encode($bytes), '+/', '-_'), '=');

        return $encode($payload) . '.' . $encode((string) $sign($payload, $query, null));
    }

    /**
     * Return the bytes of a base64url part.
     *
     * @param  string  $part
     * @return string
     */
    private static function decoded(string $part): string
    {
        return (string) \base64_decode(\strtr($part, '-_', '+/'), true);
    }

    /**
     * Assert the callback is refused for its cursor, with the one message.
     *
     * @param  \Closure(): mixed  $callback
     * @param  string  $message
     * @return void
     */
    private static function assertRefused(\Closure $callback, string $message = ''): void
    {
        try {
            $callback();
            self::fail('A cursor was read that should be refused. ' . $message);
        } catch (InvalidReviewCursorException $exception) {
            self::assertSame('The access review cursor is not valid for this review.', $exception->getMessage());
        }
    }
}
