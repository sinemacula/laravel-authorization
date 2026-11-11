<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\ReviewExportException;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\JsonLinesExport;
use SineMacula\Laravel\Authorization\Reviews\Support\PageRead;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Fixtures\Reviews\TrickleStream;
use Tests\TestCase;

/**
 * Feature tests for the JSON Lines a review is exported as: a header naming the
 * query, its scope and instants once, one line a row, and a footer of the rows
 * written and whether the review was complete; each line one object, slashes
 * and Unicode left unescaped, line separators escaped, invalid UTF-8 refused;
 * written whole to a stream or handed to a callback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(JsonLinesExport::class)]
final class JsonLinesExportTest extends TestCase
{
    /** @var string The scheme the trickling stream is registered under. */
    private const string SCHEME = 'review-trickle';

    /**
     * The header names the schema version, the query, the scope with its tenant
     * and application selection, the review's instant, when the scan began and
     * the live consistency mode, for every scope.
     *
     * @return void
     */
    public function testTheHeaderNamesTheReviewAndItsScope(): void
    {
        $at    = CarbonImmutable::parse('2026-11-08 12:00:00.000001', 'UTC');
        $start = CarbonImmutable::parse('2026-11-08 13:00:00', 'Europe/London');

        $any   = ['selection' => 'any', 'name' => null];
        $none  = ['selection' => 'none', 'name' => null];
        $named = ['selection' => 'named', 'name' => 'web'];

        $expected = [
            [ReviewScope::everywhere(), ['selection' => 'everywhere', 'tenant' => null, 'application' => $any]],
            [ReviewScope::appliesIn(null, ApplicationSelector::none()), ['selection' => 'applies_in', 'tenant' => null, 'application' => $none]],
            [
                ReviewScope::rootedWithin(new Reference('tenant', 't'), ApplicationSelector::named('web')),
                ['selection' => 'rooted_within', 'tenant' => ['type' => 'tenant', 'id' => 't'], 'application' => $named],
            ],
        ];

        foreach ($expected as [$scope, $shape]) {
            self::assertSame(
                [
                    'record'          => 'header',
                    'version'         => 1,
                    'query'           => 'granted_by',
                    'scope'           => $shape,
                    'reviewed_at'     => '2026-11-08T12:00:00.000001Z',
                    'scan_started_at' => '2026-11-08T13:00:00.000000Z',
                    'consistency'     => 'live',
                ],
                JsonLinesExport::header(ReviewQuery::grantedBy(new Reference('u', 'a'), $scope), $at, $start),
            );
        }
    }

    /**
     * The header of a review of holdings filtered by an action names the action
     * and says its rows cover only the stored grants, after every other field;
     * an unfiltered review's header has neither key.
     *
     * @return void
     */
    public function testTheHeaderOfAFilteredReviewNamesItsAction(): void
    {
        $at       = CarbonImmutable::parse('2026-11-08 12:00:00', 'UTC');
        $holdings = ReviewQuery::holdings(new Reference('u', 'a'), ReviewScope::everywhere());
        $filtered = JsonLinesExport::header($holdings->forAction('audit:read'), $at, $at);
        $plain    = JsonLinesExport::header($holdings, $at, $at);

        self::assertSame(['audit:read', true], [$filtered['action'], $filtered['stored_inventory_only']]);
        self::assertSame(['consistency', 'action', 'stored_inventory_only'], \array_slice(\array_keys($filtered), -3));
        self::assertSame($plain, \array_diff_key($filtered, ['action' => true, 'stored_inventory_only' => true]));
        self::assertSame('consistency', \array_key_last($plain));
        self::assertSame('holdings', $plain['query']);
    }

    /**
     * A line is one JSON object and a line feed, its slashes and Unicode left
     * as they are and its line separators escaped, and invalid UTF-8 is refused
     * rather than replaced.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testALineIsOneObjectAndRefusesInvalidUtf8(): void
    {
        self::assertSame("{\"a\":\"b/c \u{e4} \\u2028 \\n\"}\n", JsonLinesExport::encode(['a' => "b/c \u{e4} \u{2028} \n"]));

        $this->expectException(\JsonException::class);

        JsonLinesExport::encode(['a' => "\xff"]);
    }

    /**
     * An export writes the header once, before the first page's rows, even when
     * that page has none, then every page's rows, then the footer of the rows
     * written and whether every page was complete, and returns how many rows it
     * wrote.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExportWritesItsHeaderRowsAndFooter(): void
    {
        Carbon::setTestNow(CarbonImmutable::parse('2026-11-08 12:00:00', 'UTC'));

        $at    = CarbonImmutable::now('UTC');
        $lines = [];
        $pages = [new PageRead([], null, true, $at), new PageRead([self::row('a'), self::row('b')], null, false, $at), new PageRead([self::row('c')], null, true, $at)];

        $written = JsonLinesExport::into(static function (string $line) use (&$lines): void {
            $lines[] = \json_decode($line, true, 512, \JSON_THROW_ON_ERROR);
        })->write(ReviewQuery::grantedBy(new Reference('u', 'a'), ReviewScope::everywhere()), $pages, $at);

        Carbon::setTestNow();

        self::assertSame(3, $written);
        self::assertSame(['header', 'row', 'row', 'row', 'footer'], \array_column($lines, 'record'));
        self::assertSame(['a', 'b', 'c'], \array_column(\array_slice($lines, 1, 3), 'row_key'));
        self::assertSame(['record' => 'row', ...self::row('a')->toArray()], $lines[1]);
        self::assertSame(['record' => 'footer', 'version' => 1, 'rows' => 3, 'scan_ended_at' => '2026-11-08T12:00:00.000000Z', 'complete' => false], $lines[4]);
    }

    /**
     * A stream is written every line whole, however little it takes of each
     * write, and a sink that is neither a stream nor a callback is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStreamIsWrittenWholeAndAnythingElseRefused(): void
    {
        $file = \tempnam(\sys_get_temp_dir(), 'review');

        self::assertIsString($file);

        \stream_wrapper_register(self::SCHEME, TrickleStream::class);

        try {
            $trickle = \fopen(self::SCHEME . '://local' . $file, 'wb');

            self::assertIsResource($trickle);

            JsonLinesExport::into($trickle)->write(ReviewQuery::grantedBy(new Reference('u', 'a'), ReviewScope::everywhere()), [], CarbonImmutable::now('UTC'));

            self::assertStringStartsWith('{"record":"footer","version":1,"rows":0,', (string) \file_get_contents($file));
        } finally {
            \stream_wrapper_unregister(self::SCHEME);
            @\unlink($file);
        }

        $closed = \fopen('php://memory', 'wb');

        self::assertIsResource($closed);

        \fclose($closed);

        foreach (['php://memory', $closed, 42, \stream_context_create()] as $sink) {
            try {
                JsonLinesExport::into($sink);
                self::fail('A sink that is no stream or callback was used.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('An access review is exported to a writable stream resource or a callback.', $exception->getMessage());
            }
        }
    }

    /**
     * A stream that takes nothing of a line fails the export.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStreamThatTakesNothingFailsTheExport(): void
    {
        \stream_wrapper_register(self::SCHEME, TrickleStream::class);

        try {
            $stalled = \fopen(self::SCHEME . '://local', 'wb');

            self::assertIsResource($stalled);

            $this->expectExceptionObject(ReviewExportException::unwritable());

            JsonLinesExport::into($stalled)->write(ReviewQuery::grantedBy(new Reference('u', 'a'), ReviewScope::everywhere()), [], CarbonImmutable::now('UTC'));
        } finally {
            \stream_wrapper_unregister(self::SCHEME);
        }
    }

    /**
     * Return a row with the key.
     *
     * @param  string  $key
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewRow
     */
    private static function row(string $key): ReviewRow
    {
        $reference = new Reference('user', 'u/1');

        return new ReviewRow(
            $key,
            $reference,
            $reference,
            new Reference('role', 'r'),
            SourceKind::ROLE_GRANT,
            's',
            null,
            null,
            [],
            [],
            ['created_at' => null, 'updated_at' => null, 'expires_at' => null, 'route_expires_at' => null],
            null,
            GrantState::LIVE,
        );
    }
}
