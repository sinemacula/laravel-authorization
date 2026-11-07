<?php

declare(strict_types = 1);

namespace Tests\Unit\Query;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\Conditions;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;

/**
 * Unit tests for how the scope's conditions are joined and simplified.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Conditions::class)]
final class ConditionsTest extends TestCase
{
    /**
     * A conjunction drops every condition every row meets, and repeats, and is
     * no row's when one is.
     *
     * @return void
     */
    public function testAConjunctionSimplifies(): void
    {
        self::assertSame(QueryAuthorizer::EVERY_ROW, Conditions::all([]));
        self::assertSame(QueryAuthorizer::EVERY_ROW, Conditions::all([QueryAuthorizer::EVERY_ROW]));
        self::assertSame('a', Conditions::all(['a', QueryAuthorizer::EVERY_ROW, 'a']));
        self::assertSame('(a AND b)', Conditions::all(['a', 'b']));
        self::assertSame(QueryAuthorizer::NO_ROW, Conditions::all(['a', QueryAuthorizer::NO_ROW]));
    }

    /**
     * A conjunction and a disjunction left with one condition after dropping
     * the constants before it, or a repeat, return that condition alone.
     *
     * @return void
     */
    public function testALoneConditionAfterTheDroppedOnesIsReturned(): void
    {
        self::assertSame('a', Conditions::all([QueryAuthorizer::EVERY_ROW, 'a']));
        self::assertSame('(a AND b)', Conditions::all(['a', 'a', 'b']));
        self::assertSame('a', Conditions::any([QueryAuthorizer::NO_ROW, 'a']));
        self::assertSame('(a OR b)', Conditions::any(['a', 'a', 'b']));
    }

    /**
     * A disjunction drops every condition no row meets, and repeats, and is
     * every row's when one is.
     *
     * @return void
     */
    public function testADisjunctionSimplifies(): void
    {
        self::assertSame(QueryAuthorizer::NO_ROW, Conditions::any([]));
        self::assertSame(QueryAuthorizer::NO_ROW, Conditions::any([QueryAuthorizer::NO_ROW]));
        self::assertSame('a', Conditions::any(['a', QueryAuthorizer::NO_ROW, 'a']));
        self::assertSame('(a OR b)', Conditions::any(['a', 'b']));
        self::assertSame(QueryAuthorizer::EVERY_ROW, Conditions::any(['a', QueryAuthorizer::EVERY_ROW]));
    }

    /**
     * A negation swaps the constants, and treats a condition the database
     * cannot decide as met before negating it, so it keeps no row.
     *
     * @return void
     */
    public function testANegationFailsClosed(): void
    {
        self::assertSame(QueryAuthorizer::NO_ROW, Conditions::not(QueryAuthorizer::EVERY_ROW));
        self::assertSame(QueryAuthorizer::EVERY_ROW, Conditions::not(QueryAuthorizer::NO_ROW));
        self::assertSame('NOT COALESCE(a, 1 = 1)', Conditions::not('a'));
    }
}
