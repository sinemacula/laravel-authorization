<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;

/**
 * Unit tests for `ContextKeyType`, the type of a declared context key and the
 * operators that suit it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ContextKeyType::class)]
final class ContextKeyTypeTest extends TestCase
{
    /**
     * The types are backed by the names policies and configuration use.
     *
     * @return void
     */
    public function testTypesAreBackedByStableStrings(): void
    {
        $values = \array_map(static fn (ContextKeyType $type): string => $type->value, ContextKeyType::cases());

        self::assertSame(['string', 'number', 'bool', 'time', 'ip', 'list'], $values);
    }

    /**
     * Provide each type with the operators that suit it, besides `null`.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Authorization\Enums\ContextKeyType, list<string>}>
     */
    public static function operatorProvider(): iterable
    {
        yield 'string' => [ContextKeyType::STRING, ['eq', 'neq', 'in', 'not_in', 'starts_with', 'ends_with', 'like']];
        yield 'number' => [ContextKeyType::NUMBER, ['eq', 'neq', 'in', 'not_in', 'gt', 'gte', 'lt', 'lte']];
        yield 'bool' => [ContextKeyType::BOOL, ['eq', 'neq', 'bool']];
        yield 'time' => [ContextKeyType::TIME, ['before', 'after', 'between']];
        yield 'ip' => [ContextKeyType::IP, ['eq', 'neq', 'in', 'not_in', 'ip_in', 'ip_not_in']];
        yield 'list' => [ContextKeyType::LIST, ['any_value_in', 'all_values_in']];
    }

    /**
     * Each type lists the operators that suit it, and suits exactly those, in
     * either form, and `null`; every other operator suits it in neither form.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\ContextKeyType  $type
     * @param  list<string>  $operators
     * @return void
     */
    #[DataProvider('operatorProvider')]
    public function testEachTypeSuitsItsOperators(ContextKeyType $type, array $operators): void
    {
        self::assertSame($operators, $type->operators());
        self::assertTrue($type->suits('null'));

        foreach (ConditionEvaluator::OPERATORS as $operator) {
            $suits = $operator === 'null' || \in_array($operator, $operators, true);

            self::assertSame($suits, $type->suits($operator), $operator);
            self::assertSame($suits && $operator !== 'null', $type->suits($operator . ConditionEvaluator::IF_EXISTS), $operator . ConditionEvaluator::IF_EXISTS);
        }
    }

    /**
     * An unknown operator suits no type.
     *
     * @return void
     */
    public function testAnUnknownOperatorSuitsNoType(): void
    {
        foreach (ContextKeyType::cases() as $type) {
            self::assertFalse($type->suits('bogus'));
            self::assertFalse($type->suits(''));
            self::assertFalse($type->suits('null_if_exists'));
            self::assertFalse($type->suits('EQ'));
        }
    }
}
