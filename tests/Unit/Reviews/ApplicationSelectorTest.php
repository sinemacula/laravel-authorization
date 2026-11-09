<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\TestCase;

/**
 * Unit tests for the application selector of an access review: none, a named
 * application, or any, each said explicitly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationSelector::class)]
final class ApplicationSelectorTest extends TestCase
{
    /**
     * Each selection names itself, and only a named one carries its
     * application.
     *
     * @return void
     */
    public function testEachSelectionNamesItself(): void
    {
        self::assertSame(['none', null, false], [ApplicationSelector::none()->selection(), ApplicationSelector::none()->application, ApplicationSelector::none()->isAny]);
        self::assertSame(
            ['named', 'web', false],
            [ApplicationSelector::named('web')->selection(), ApplicationSelector::named('web')->application, ApplicationSelector::named('web')->isAny],
        );
        self::assertSame(['any', null, true], [ApplicationSelector::any()->selection(), ApplicationSelector::any()->application, ApplicationSelector::any()->isAny]);
        self::assertSame(['none', 'named', 'any'], [ApplicationSelector::NONE, ApplicationSelector::NAMED, ApplicationSelector::ANY]);
    }

    /**
     * An application is named by at least one byte and at most a reference's
     * bound.
     *
     * @return void
     */
    public function testAnApplicationIsNamedByABoundedName(): void
    {
        self::assertSame(\str_repeat('a', Reference::MAX_BYTES), ApplicationSelector::named(\str_repeat('a', Reference::MAX_BYTES))->application);

        foreach (['', \str_repeat('a', Reference::MAX_BYTES + 1)] as $name) {
            try {
                ApplicationSelector::named($name);
                self::fail('An unbounded application was named.');
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    /**
     * None keeps only the grants for every application, a named one those and
     * its own, and any every grant.
     *
     * @return void
     */
    public function testEachSelectionConstrainsAGrantQuery(): void
    {
        $query = static fn (ApplicationSelector $selector): array => [
            \str_replace(['"', '`'], '', $selector->constrain(DB::table('grants'), 'grants')->toSql()),
            $selector->constrain(DB::table('grants'), 'grants')->getBindings(),
        ];

        self::assertSame(['select * from grants where (grants.application is null)', []], $query(ApplicationSelector::none()));
        self::assertSame(['select * from grants where (grants.application is null or grants.application = ?)', ['web']], $query(ApplicationSelector::named('web')));
        self::assertSame(['select * from grants', []], $query(ApplicationSelector::any()));
    }
}
