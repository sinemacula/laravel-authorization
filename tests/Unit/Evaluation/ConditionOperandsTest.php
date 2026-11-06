<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\ConditionOperands;
use SineMacula\Laravel\Authorization\Evaluation\IpRanges;

/**
 * Unit tests for the operand and value forms of the condition operators.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ConditionOperands::class)]
#[CoversClass(IpRanges::class)]
final class ConditionOperandsTest extends TestCase
{
    /**
     * Provide one valid and one invalid literal operand for every operator.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: mixed}>
     */
    public static function operandProvider(): iterable
    {
        yield 'eq' => ['eq', 'x', ['x']];
        yield 'neq' => ['neq', 1, null];
        yield 'in' => ['in', ['a'], []];
        yield 'not_in' => ['not_in', [1, 2], ['a', null]];
        yield 'starts_with' => ['starts_with', 'a', ''];
        yield 'ends_with' => ['ends_with', 'a', 5];
        yield 'like' => ['like', 'a*', ['a*']];
        yield 'gt' => ['gt', 5, 'abc'];
        yield 'gte' => ['gte', '5.5', \INF];
        yield 'lt' => ['lt', 1.5, true];
        yield 'lte' => ['lte', 0, null];
        yield 'before' => ['before', '2026-01-01', 'not-a-time'];
        yield 'after' => ['after', 1000, null];
        yield 'between' => ['between', [100, 200], [100]];
        yield 'bool' => ['bool', 'false', 'yes'];
        yield 'null' => ['null', false, 'true'];
        yield 'ip_in' => ['ip_in', '10.0.0.0/8', '10.0.0.0/33'];
        yield 'ip_not_in' => ['ip_not_in', ['10.0.0.0/8'], []];
        yield 'any_value_in' => ['any_value_in', ['a'], 'a'];
        yield 'all_values_in' => ['all_values_in', ['a', true], [['a']]];
    }

    /**
     * isValid() accepts an operand of the type each operator takes and refuses
     * one of another type.
     *
     * @param  string  $operator
     * @param  mixed  $valid
     * @param  mixed  $invalid
     * @return void
     */
    #[DataProvider('operandProvider')]
    public function testIsValid(string $operator, mixed $valid, mixed $invalid): void
    {
        self::assertTrue(ConditionOperands::isValid($operator, $valid));
        self::assertFalse(ConditionOperands::isValid($operator, $invalid));
    }

    /**
     * Every operator is covered by the provider, and an unknown operator takes
     * no operand at all.
     *
     * @return void
     */
    public function testEveryOperatorHasARuleAndUnknownOnesTakeNothing(): void
    {
        self::assertSame(ConditionEvaluator::OPERATORS, \array_keys(\iterator_to_array(self::operandProvider())));

        foreach (['bogus', 'cidr', 'string_like', 'not_null', 'eq_if_exists'] as $operator) {
            self::assertFalse(ConditionOperands::isValid($operator, 'x'), $operator);
            self::assertFalse(ConditionOperands::isValid($operator, true), $operator);
        }
    }

    /**
     * Provide values with whether they are a list of scalars and whether they
     * are a set operand: a non-empty list of scalars.
     *
     * @return iterable<string, array{0: mixed, 1: bool, 2: bool}>
     */
    public static function listProvider(): iterable
    {
        yield 'empty list' => [[], true, false];
        yield 'strings' => [['a', 'b'], true, true];
        yield 'mixed scalars' => [['a', 1, 1.5, false], true, true];
        yield 'null element' => [['a', null], false, false];
        yield 'list element' => [[['a']], false, false];
        yield 'object element' => [[new \stdClass], false, false];
        yield 'map' => [['k' => 'a'], false, false];
        yield 'list not from zero' => [[1 => 'a'], false, false];
        yield 'scalar' => ['a', false, false];
        yield 'null' => [null, false, false];
    }

    /**
     * isScalarList() and isScalarSet() read lists strictly: every element a
     * scalar, and a set never empty.
     *
     * @param  mixed  $value
     * @param  bool  $isList
     * @param  bool  $isSet
     * @return void
     */
    #[DataProvider('listProvider')]
    public function testScalarListsAndSets(mixed $value, bool $isList, bool $isSet): void
    {
        self::assertSame($isList, ConditionOperands::isScalarList($value));
        self::assertSame($isSet, ConditionOperands::isScalarSet($value));
    }

    /**
     * Provide values with whether they are a string operand: a non-empty string
     * without a NUL byte.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function stringOperandProvider(): iterable
    {
        yield 'letter' => ['a', true];
        yield 'zero' => ['0', true];
        yield 'space' => [' ', true];
        yield 'empty' => ['', false];
        yield 'nul' => ["a\0b", false];
        yield 'only nul' => ["\0", false];
        yield 'null' => [null, false];
        yield 'int' => [1, false];
        yield 'list' => [['a'], false];
    }

    /**
     * isStringOperand() accepts a string with at least one character and no NUL
     * byte only.
     *
     * @param  mixed  $value
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('stringOperandProvider')]
    public function testIsStringOperand(mixed $value, bool $expected): void
    {
        self::assertSame($expected, ConditionOperands::isStringOperand($value));
    }

    /**
     * isNumber() accepts finite numbers and numeric strings only.
     *
     * @return void
     */
    public function testIsNumber(): void
    {
        foreach ([0, -3, 1.5, '42', '-1.5', '1e3'] as $number) {
            self::assertTrue(ConditionOperands::isNumber($number));
        }

        foreach ([\NAN, \INF, -\INF, '1e999', 'abc', '', true, null, [1]] as $value) {
            self::assertFalse(ConditionOperands::isNumber($value));
        }
    }

    /**
     * isBooleanForm() and isTrue() read the eight boolean forms, and nothing
     * else.
     *
     * @return void
     */
    public function testBooleanForms(): void
    {
        foreach ([true, 1, '1', 'true'] as $form) {
            self::assertTrue(ConditionOperands::isBooleanForm($form));
            self::assertTrue(ConditionOperands::isTrue($form));
        }

        foreach ([false, 0, '0', 'false'] as $form) {
            self::assertTrue(ConditionOperands::isBooleanForm($form));
            self::assertFalse(ConditionOperands::isTrue($form));
        }

        foreach (['yes', 'TRUE', 2, -1, 1.0, null, '', [true]] as $value) {
            self::assertFalse(ConditionOperands::isBooleanForm($value));
            self::assertFalse(ConditionOperands::isTrue($value));
        }
    }

    /**
     * toTimestamp() reads every time-like form, and refuses a string holding a
     * NUL byte, which `strtotime()` would read only up to the byte.
     *
     * @return void
     */
    public function testTimes(): void
    {
        self::assertSame(1000, ConditionOperands::toTimestamp(1000));
        self::assertSame(999, ConditionOperands::toTimestamp(999.9));
        self::assertSame(1000, ConditionOperands::toTimestamp(new \DateTimeImmutable('@1000')));
        self::assertSame(86400, ConditionOperands::toTimestamp('1970-01-02 00:00:00 UTC'));

        foreach (['', 'not-a-time', "1970-01-02\0", "1970-01-02\0junk", null, true, \NAN, \INF, [1000]] as $value) {
            self::assertNull(ConditionOperands::toTimestamp($value));
        }
    }

    /**
     * Provide operands with whether they are a pair of time bounds.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function timeRangeProvider(): iterable
    {
        yield 'pair' => [[100, '2026-01-01'], true];
        yield 'one bound' => [[100], false];
        yield 'missing lower key' => [[1 => 100, 2 => 200], false];
        yield 'missing upper key' => [[0 => 100, 2 => 200], false];
        yield 'bad lower bound' => [['bad', 200], false];
        yield 'bad upper bound' => [[100, 'bad'], false];
        yield 'string' => ['100', false];
    }

    /**
     * isTimeRange() reads a pair of time-like bounds at keys 0 and 1.
     *
     * @param  mixed  $operand
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('timeRangeProvider')]
    public function testIsTimeRange(mixed $operand, bool $expected): void
    {
        self::assertSame($expected, ConditionOperands::isTimeRange($operand));
    }
}
