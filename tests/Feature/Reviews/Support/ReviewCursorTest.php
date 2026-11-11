<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Carbon\CarbonImmutable;
use Illuminate\Encryption\MissingAppKeyException;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Exceptions\InvalidReviewCursorException;
use SineMacula\Laravel\Authorization\Models\Permission;
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
     * The signing key is the HMAC-SHA256 of the cursor context under the
     * application key's bytes: a `base64:` key decoded, strictly, and any other
     * key, one that does not decode included, as it is given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSigningKeyIsDerivedFromTheApplicationKeysBytes(): void
    {
        $query    = self::reviewed();
        $position = new ReviewPosition(CarbonImmutable::parse('2026-11-08 12:00:00', 'UTC'), [0]);
        $derived  = static fn (string $bytes): ReviewCursor => new ReviewCursor(\hash_hmac('sha256', 'sinemacula/laravel-authorization:access-review-cursor', $bytes, true));

        $keys = [
            'base64:' . \base64_encode(\str_repeat('k', 32)) => \str_repeat('k', 32),
            'base64:' . \base64_encode('plain-text-key')     => 'plain-text-key',
            'plain-text-key'                                 => 'plain-text-key',
            'base64:!!!'                                     => 'base64:!!!',
            'base64:YQ=!'                                    => 'base64:YQ=!',
        ];

        foreach ($keys as $key => $bytes) {
            config(['app.key' => $key]);

            $issued = ReviewCursor::forApplication()->issue($position, $query, null);

            self::assertSame([0], $derived($bytes)->read($issued, $query, null)->after, $key);
            self::assertSame([0], ReviewCursor::forApplication()->read($derived($bytes)->issue($position, $query, null), $query, null)->after, $key);
        }
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
     * Every part of what a cursor is bound to counts on its own: a cursor
     * issued for a query is refused for one that differs from it in that part
     * alone, and read for the query itself; the action a review of holdings is
     * filtered by counts too, so a cursor of an unfiltered review, or of
     * another action, is refused for it, and the reverse.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachPartOfTheBindingIsBoundAlone(): void
    {
        $cursors = new ReviewCursor('key');
        $role    = new Reference((new Role)->getMorphClass(), '01a1be88-d4d3-72cc-b9bc-620cc97d4906');
        $ann     = self::identity('ann');
        $from    = CarbonImmutable::parse('2026-01-01', 'UTC');
        $until   = CarbonImmutable::parse('2026-02-01', 'UTC');
        $web     = ApplicationSelector::named('web');

        $all      = ReviewScope::everywhere();
        $holders  = static fn (ReviewScope $scope, bool $isDirectOnly = false): ReviewQuery => ReviewQuery::holders($role, $scope, $isDirectOnly);
        $holdings = static fn (Reference|Subject $subject): ReviewQuery => ReviewQuery::holdings($subject, $all);
        $expiring = static fn (CarbonImmutable $start, CarbonImmutable $end): ReviewQuery => ReviewQuery::expiring($all, $start, $end);
        $actor    = static fn (string $type, string $id): ReviewQuery => ReviewQuery::grantedBy(new Reference($type, $id), $all);
        $rooted   = $holders(ReviewScope::rootedWithin(self::tenant('t1')));

        $pairs = [
            'tenant key'      => [$rooted, $holders(ReviewScope::rootedWithin(self::tenant('t2')))],
            'tenant type'     => [$rooted, $holders(ReviewScope::rootedWithin(new Reference('team', 't1')))],
            'selection'       => [$rooted, $holders(ReviewScope::appliesIn(self::tenant('t1'), ApplicationSelector::any()))],
            'application'     => [$holders(ReviewScope::everywhere($web)), $holders(ReviewScope::everywhere(ApplicationSelector::named('api')))],
            'selector'        => [$holders(ReviewScope::everywhere(ApplicationSelector::none())), $holders($all)],
            'target type'     => [$holders($all), ReviewQuery::holders(new Reference((new Permission)->getMorphClass(), $role->id), $all)],
            'direct only'     => [$holders($all, true), $holders($all)],
            'about key'       => [$holdings(new Reference('u', 'a')), $holdings(new Reference('u', 'b'))],
            'about type'      => [$holdings(new Reference('u', 'a')), $holdings(new Reference('v', 'a'))],
            'mode'            => [$holdings(new Reference('u', 'a')), $holdings(new Subject(new Reference('u', 'a')))],
            'identity model'  => [$holdings(new Subject($ann, self::identity('ia'))), $holdings(new Subject($ann, self::identity('ib')))],
            'identity ref'    => [$holdings(new Subject($ann, new Reference('u', 'ia'))), $holdings(new Subject($ann, new Reference('u', 'ib')))],
            'identity type'   => [$holdings(new Subject($ann, new Reference('u', 'ia'))), $holdings(new Subject($ann, new Reference('v', 'ia')))],
            'identity absent' => [$holdings(new Subject($ann, new Reference('u', 'ia'))), $holdings(new Subject($ann))],
            'window start'    => [$expiring($from, $until), $expiring($from->addSecond(), $until)],
            'window end'      => [$expiring($from, $until), $expiring($from, $until->addSecond())],
            'actor key'       => [$actor('u', 'a'), $actor('u', 'b')],
            'actor type'      => [$actor('u', 'a'), $actor('v', 'a')],
            'action'          => [$holdings(new Reference('u', 'a'))->forAction('posts:edit'), $holdings(new Reference('u', 'a'))->forAction('posts:read')],
            'action case'     => [$holdings(new Reference('u', 'a'))->forAction('posts:edit'), $holdings(new Reference('u', 'a'))->forAction('posts:Edit')],
            'filtered'        => [$holdings(new Reference('u', 'a'))->forAction('posts:edit'), $holdings(new Reference('u', 'a'))],
            'unfiltered'      => [$holdings(new Reference('u', 'a')), $holdings(new Reference('u', 'a'))->forAction('posts:edit')],
            'action subject'  => [$holdings(new Reference('u', 'a'))->forAction('posts:edit'), $holdings(new Reference('u', 'b'))->forAction('posts:edit')],
        ];

        foreach ($pairs as $part => [$query, $other]) {
            $cursor = $cursors->issue(new ReviewPosition(CarbonImmutable::now('UTC'), [0]), $query, null);

            self::assertSame([0], $cursors->read($cursor, $query, null)->after, $part);
            self::assertRefused(static fn (): mixed => $cursors->read($cursor, $other, null), $part);
        }
    }

    /**
     * A cursor is read only in the one text that encodes it: the same bytes
     * written with a line break, padding, the standard base64 alphabet, spare
     * bits that are not zero or any character more are refused, so a cursor
     * changed in any byte is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheCanonicalTextOfACursorIsRead(): void
    {
        $cursors = new ReviewCursor('key');
        $query   = self::reviewed();
        $cursor  = $cursors->issue(new ReviewPosition(CarbonImmutable::parse('2026-11-08 12:00:01', 'UTC'), [0, "\xff\xff"]), $query, null);

        [$payload, $signature] = \explode('.', $cursor);

        // The payload's own parts are written as they are, a slash included.
        self::assertStringContainsString('"after":[0,"//8="]', self::decoded($payload));
        self::assertSame(43, \strlen($signature));
        self::assertNotSame(0, \strlen($payload) % 4);
        self::assertMatchesRegularExpression('/^.+[-_].+$/', $signature);

        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        $spare    = \substr($signature, 0, -1) . $alphabet[\strpos($alphabet, \substr($signature, -1)) ^ 1];

        self::assertSame(self::decoded($signature), self::decoded($spare));

        $variants = [
            $cursor . "\n",
            $payload . "\n." . $signature,
            $payload . '.' . $signature . '=',
            $payload . '=.' . $signature,
            $payload . '.' . \strtr($signature, '-_', '+/'),
            $payload . '.' . $spare,
            $payload . 'A.' . $signature,
            ' ' . $cursor,
        ];

        foreach ($variants as $variant) {
            self::assertRefused(static fn (): mixed => $cursors->read($variant, $query, null), \json_encode($variant, \JSON_THROW_ON_ERROR));
        }

        self::assertSame([0, "\xff\xff"], $cursors->read($cursor, $query, null)->after);
    }

    /**
     * A cursor of up to 16384 characters is read, and a longer one is refused
     * unread, however validly it is signed; and the longest sort key a review
     * gives, every part as long as a stored reference may be, issues a cursor
     * well within that.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACursorIsReadUpToItsLongestLength(): void
    {
        $cursors = new ReviewCursor('key');
        $query   = self::reviewed();
        $payload = static fn (int $spaces, int $padding): string => \sprintf(
            '{%s"v":1,"at":"2026-11-08T12:00:00.000000Z","after":[0,"%s"]}',
            \str_repeat(' ', $spaces),
            \str_repeat('A', $padding),
        );
        $fixed = \strlen($payload(0, 0));
        $room  = 12255 - $fixed;

        $longest = self::signed($cursors, $payload($room % 4, $room - $room % 4), $query);

        self::assertSame(16384, \strlen($longest));
        self::assertSame([0, \str_repeat("\x00", \intdiv(($room - $room % 4) * 3, 4))], $cursors->read($longest, $query, null)->after);

        $longer = self::signed($cursors, $payload($room % 4 + 1, $room - $room % 4), $query);

        self::assertSame(16386, \strlen($longer));
        self::assertRefused(static fn (): mixed => $cursors->read($longer, $query, null));

        $reference = \str_repeat("\u{e4}", 95) . 'x';
        $key       = [7, \str_repeat('T', 191), '01a1be88-d4d3-72cc-b9bc-620cc97d4906', $reference, $reference, 1, $reference, 1, $reference, 1, $reference, true];
        $rests     = [\str_repeat('r', 36), 99, \str_repeat($reference, 8)];
        $issued    = $cursors->issue(new ReviewPosition(CarbonImmutable::now('UTC'), [...$key, ...$rests]), $query, null);

        self::assertLessThan(16384 / 2, \strlen($issued));
        self::assertSame([...$key, ...$rests], $cursors->read($issued, $query, null)->after);
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

        foreach (['', '.', 'a', 'a.b.c', 'a+b.c', 'YQ.Y=', '.' . \str_repeat('a', 16384)] as $text) {
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
