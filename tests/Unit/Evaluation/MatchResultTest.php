<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\MatchResult;

/**
 * Unit tests for the match result value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(MatchResult::class)]
final class MatchResultTest extends TestCase
{
    /**
     * The constructor stores the outcome and defaults the detail to an empty
     * string.
     *
     * @return void
     */
    public function testConstructorDefaultsDetailToEmptyString(): void
    {
        $result = new MatchResult(MatchOutcome::UNDECIDABLE);

        self::assertSame(MatchOutcome::UNDECIDABLE, $result->outcome);
        self::assertSame('', $result->detail);
    }

    /**
     * The constructor stores the supplied detail.
     *
     * @return void
     */
    public function testConstructorStoresDetail(): void
    {
        $result = new MatchResult(MatchOutcome::INVALID, 'broken');

        self::assertSame(MatchOutcome::INVALID, $result->outcome);
        self::assertSame('broken', $result->detail);
    }

    /**
     * The constructor defaults the condition keys to null, meaning the
     * statement does not name the action and the resource.
     *
     * @return void
     */
    public function testConstructorDefaultsConditionsToNull(): void
    {
        self::assertNull((new MatchResult(MatchOutcome::MATCHES))->conditions);
        self::assertNull((new MatchResult(MatchOutcome::DOES_NOT_MATCH, 'detail'))->conditions);
    }

    /**
     * The constructor stores the supplied condition keys, each with whether it
     * held, in order.
     *
     * @return void
     */
    public function testConstructorStoresConditions(): void
    {
        $result = new MatchResult(MatchOutcome::DOES_NOT_MATCH, 'detail', ['tenant' => true, 'role' => false]);

        self::assertSame(['tenant' => true, 'role' => false], $result->conditions);
    }

    /**
     * The factories build results without condition keys.
     *
     * @return void
     */
    public function testFactoriesCarryNoConditions(): void
    {
        self::assertNull(MatchResult::matches()->conditions);
        self::assertNull(MatchResult::doesNotMatch()->conditions);
        self::assertNull(MatchResult::doesNotMatch('detail')->conditions);
        self::assertNull(MatchResult::undecidable('detail')->conditions);
        self::assertNull(MatchResult::invalid('detail')->conditions);
        self::assertNull(MatchResult::fromBool(true)->conditions);
        self::assertNull(MatchResult::fromBool(false)->conditions);
    }

    /**
     * withConditions() returns a new result with the condition keys, keeping
     * the outcome and the detail, and leaves the original untouched.
     *
     * @return void
     */
    public function testWithConditionsReturnsCopyWithConditions(): void
    {
        $original = MatchResult::undecidable('key \'ip\' is missing from the context');
        $result   = $original->withConditions(['tenant' => true, 'ip' => false]);

        self::assertNotSame($original, $result);
        self::assertSame(MatchOutcome::UNDECIDABLE, $result->outcome);
        self::assertSame('key \'ip\' is missing from the context', $result->detail);
        self::assertSame(['tenant' => true, 'ip' => false], $result->conditions);
        self::assertNull($original->conditions);
    }

    /**
     * withConditions() records an empty map as no keys tested, distinct from
     * null, and replaces any keys the result already carried.
     *
     * @return void
     */
    public function testWithConditionsStoresEmptyAndReplacesExisting(): void
    {
        $empty = MatchResult::matches()->withConditions([]);

        self::assertSame([], $empty->conditions);
        self::assertTrue($empty->holds());

        $replaced = (new MatchResult(MatchOutcome::DOES_NOT_MATCH, '', ['a' => true]))->withConditions(['b' => false]);

        self::assertSame(['b' => false], $replaced->conditions);
    }

    /**
     * withConditions() never changes the shared plain results.
     *
     * @return void
     */
    public function testWithConditionsLeavesSharedResultsUntouched(): void
    {
        MatchResult::matches()->withConditions(['tenant' => true]);
        MatchResult::doesNotMatch()->withConditions(['tenant' => false]);

        self::assertNull(MatchResult::matches()->conditions);
        self::assertNull(MatchResult::doesNotMatch()->conditions);
    }

    /**
     * and() carries the condition keys of the result it keeps, and none when it
     * keeps one that has none.
     *
     * @return void
     */
    public function testAndKeepsConditionsOfKeptResult(): void
    {
        $failed   = MatchResult::doesNotMatch()->withConditions(['tenant' => false]);
        $combined = MatchResult::matches()->and($failed);

        self::assertSame(['tenant' => false], $combined->conditions);
        self::assertNull($failed->and(MatchResult::invalid('broken'))->conditions);
    }

    /**
     * matches() builds a matching result with no detail.
     *
     * @return void
     */
    public function testMatchesFactory(): void
    {
        $result = MatchResult::matches();

        self::assertSame(MatchOutcome::MATCHES, $result->outcome);
        self::assertSame('', $result->detail);
        self::assertTrue($result->holds());
    }

    /**
     * doesNotMatch() defaults the detail to an empty string.
     *
     * @return void
     */
    public function testDoesNotMatchFactoryWithoutDetail(): void
    {
        $result = MatchResult::doesNotMatch();

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $result->outcome);
        self::assertSame('', $result->detail);
        self::assertFalse($result->holds());
    }

    /**
     * doesNotMatch() stores the supplied detail.
     *
     * @return void
     */
    public function testDoesNotMatchFactoryWithDetail(): void
    {
        $result = MatchResult::doesNotMatch('condition \'tenant\' not satisfied');

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $result->outcome);
        self::assertSame('condition \'tenant\' not satisfied', $result->detail);
        self::assertFalse($result->holds());
    }

    /**
     * undecidable() builds an undecidable result with the supplied detail.
     *
     * @return void
     */
    public function testUndecidableFactory(): void
    {
        $result = MatchResult::undecidable('context key \'tenant\' is missing');

        self::assertSame(MatchOutcome::UNDECIDABLE, $result->outcome);
        self::assertSame('context key \'tenant\' is missing', $result->detail);
        self::assertFalse($result->holds());
    }

    /**
     * invalid() builds an invalid result with the supplied detail.
     *
     * @return void
     */
    public function testInvalidFactory(): void
    {
        $result = MatchResult::invalid('unknown operator \'nope\'');

        self::assertSame(MatchOutcome::INVALID, $result->outcome);
        self::assertSame('unknown operator \'nope\'', $result->detail);
        self::assertFalse($result->holds());
    }

    /**
     * fromBool() maps true to a match with no detail.
     *
     * @return void
     */
    public function testFromBoolTrueMatches(): void
    {
        $result = MatchResult::fromBool(true);

        self::assertSame(MatchOutcome::MATCHES, $result->outcome);
        self::assertSame('', $result->detail);
        self::assertTrue($result->holds());
    }

    /**
     * fromBool() maps false to a non-match with no detail.
     *
     * @return void
     */
    public function testFromBoolFalseDoesNotMatch(): void
    {
        $result = MatchResult::fromBool(false);

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $result->outcome);
        self::assertSame('', $result->detail);
        self::assertFalse($result->holds());
    }

    /**
     * holds() is true for the matching outcome only.
     *
     * @return void
     */
    public function testHoldsOnlyForMatches(): void
    {
        self::assertTrue((new MatchResult(MatchOutcome::MATCHES))->holds());
        self::assertFalse((new MatchResult(MatchOutcome::DOES_NOT_MATCH))->holds());
        self::assertFalse((new MatchResult(MatchOutcome::UNDECIDABLE))->holds());
        self::assertFalse((new MatchResult(MatchOutcome::INVALID))->holds());
    }

    /**
     * Data provider for every ordered pair of outcomes, by backing value, with
     * the side of the conjunction whose result and() keeps.
     *
     * @return \Generator<string, array{0: string, 1: string, 2: string}>
     */
    public static function conjunctionProvider(): iterable
    {
        yield 'matches and matches' => ['matches', 'matches', 'left'];
        yield 'matches and does not match' => ['matches', 'does_not_match', 'right'];
        yield 'matches and undecidable' => ['matches', 'undecidable', 'right'];
        yield 'matches and invalid' => ['matches', 'invalid', 'right'];
        yield 'does not match and matches' => ['does_not_match', 'matches', 'left'];
        yield 'does not match and does not match' => ['does_not_match', 'does_not_match', 'left'];
        yield 'does not match and undecidable' => ['does_not_match', 'undecidable', 'left'];
        yield 'does not match and invalid' => ['does_not_match', 'invalid', 'right'];
        yield 'undecidable and matches' => ['undecidable', 'matches', 'left'];
        yield 'undecidable and does not match' => ['undecidable', 'does_not_match', 'right'];
        yield 'undecidable and undecidable' => ['undecidable', 'undecidable', 'left'];
        yield 'undecidable and invalid' => ['undecidable', 'invalid', 'right'];
        yield 'invalid and matches' => ['invalid', 'matches', 'left'];
        yield 'invalid and does not match' => ['invalid', 'does_not_match', 'left'];
        yield 'invalid and undecidable' => ['invalid', 'undecidable', 'left'];
        yield 'invalid and invalid' => ['invalid', 'invalid', 'left'];
    }

    /**
     * and() keeps the result with the higher precedence, keeps the receiver on
     * a tie, and preserves the kept result's detail.
     *
     * @param  string  $leftValue
     * @param  string  $rightValue
     * @param  string  $kept
     * @return void
     */
    #[DataProvider('conjunctionProvider')]
    public function testAndKeepsHigherPrecedence(string $leftValue, string $rightValue, string $kept): void
    {
        $left  = MatchOutcome::from($leftValue);
        $right = MatchOutcome::from($rightValue);

        $receiver = new MatchResult($left, 'left detail');
        $other    = new MatchResult($right, 'right detail');

        $combined = $receiver->and($other);

        self::assertSame($kept === 'left' ? $receiver : $other, $combined);
        self::assertSame($kept === 'left' ? $left : $right, $combined->outcome);
        self::assertSame($kept . ' detail', $combined->detail);
    }

    /**
     * and() chains across several parts so the strongest outcome wins
     * regardless of position.
     *
     * @return void
     */
    public function testAndChainsToStrongestOutcome(): void
    {
        $combined = MatchResult::matches()
            ->and(MatchResult::undecidable('first undecidable'))
            ->and(MatchResult::doesNotMatch('definite failure'))
            ->and(MatchResult::undecidable('second undecidable'))
            ->and(MatchResult::matches());

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $combined->outcome);
        self::assertSame('definite failure', $combined->detail);
    }

    /**
     * The plain results are shared: matches() is one instance, and
     * doesNotMatch() is one instance per detail.
     *
     * @return void
     */
    public function testPlainResultsAreShared(): void
    {
        self::assertSame(MatchResult::matches(), MatchResult::matches());
        self::assertSame(MatchResult::doesNotMatch(), MatchResult::doesNotMatch(''));
        self::assertSame(MatchResult::doesNotMatch('a'), MatchResult::doesNotMatch('a'));
        self::assertNotSame(MatchResult::doesNotMatch('a'), MatchResult::doesNotMatch('b'));
        self::assertSame('b', MatchResult::doesNotMatch('b')->detail);
        self::assertSame(MatchResult::matches(), MatchResult::fromBool(true));
        self::assertSame(MatchResult::doesNotMatch(), MatchResult::fromBool(false));
    }
}
