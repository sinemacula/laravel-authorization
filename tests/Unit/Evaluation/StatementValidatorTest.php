<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\StatementValidator;

/**
 * Unit tests for the statement validator.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(StatementValidator::class)]
final class StatementValidatorTest extends TestCase
{
    /**
     * KEYS lists exactly the four keys a statement may carry.
     *
     * @return void
     */
    public function testKeysConstant(): void
    {
        self::assertSame(['effect', 'actions', 'resources', 'conditions'], StatementValidator::KEYS);
    }

    /**
     * assertKnownKeys() accepts a statement carrying every known key.
     *
     * @return void
     */
    public function testAssertKnownKeysAcceptsEveryKnownKey(): void
    {
        StatementValidator::assertKnownKeys([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'resources'  => ['*'],
            'conditions' => ['tenant' => 'org-1'],
        ]);

        $this->addToAssertionCount(1);
    }

    /**
     * assertKnownKeys() accepts a statement carrying a subset of the known
     * keys, and an empty one.
     *
     * @return void
     */
    public function testAssertKnownKeysAcceptsSubsetOfKnownKeys(): void
    {
        StatementValidator::assertKnownKeys(['effect' => 'deny', 'actions' => ['x']]);
        StatementValidator::assertKnownKeys([]);

        $this->addToAssertionCount(2);
    }

    /**
     * assertKnownKeys() refuses a single unknown key, naming it.
     *
     * @return void
     */
    public function testAssertKnownKeysRefusesUnknownKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement has unknown keys: condition.');

        StatementValidator::assertKnownKeys([
            'effect'    => 'allow',
            'actions'   => ['x'],
            'condition' => ['tenant' => 'org-1'],
        ]);
    }

    /**
     * assertKnownKeys() lists every unknown key, in order, separated by commas.
     *
     * @return void
     */
    public function testAssertKnownKeysListsEveryUnknownKey(): void
    {
        try {
            StatementValidator::assertKnownKeys([
                'effect'   => 'allow',
                'Action'   => ['x'],
                'actions'  => ['x'],
                'resource' => ['doc:1'],
            ]);
            self::fail('Expected an InvalidArgumentException.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Policy statement has unknown keys: Action, resource.', $exception->getMessage());
        }
    }

    /**
     * assertKnownKeys() refuses numeric keys, as a list-shaped statement would
     * carry.
     *
     * @return void
     */
    public function testAssertKnownKeysRefusesNumericKeys(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement has unknown keys: 0, 1.');

        StatementValidator::assertKnownKeys(['allow', ['x']]);
    }

    /**
     * assertKnownKeys() refuses a numeric key mixed with known keys.
     *
     * @return void
     */
    public function testAssertKnownKeysRefusesNumericKeyAlongsideKnownKeys(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement has unknown keys: 7.');

        StatementValidator::assertKnownKeys(['effect' => 'allow', 7 => 'x']);
    }

    /**
     * Data provider for conditions that are plain values rather than operator
     * maps.
     *
     * @return \Generator<string, array{0: mixed}>
     */
    public static function plainValueProvider(): iterable
    {
        yield 'string' => ['org-1'];
        yield 'empty string' => [''];
        yield 'interpolated' => ['${principal.id}'];
        yield 'escaped reference' => ['\${principal.id}'];
        yield 'integer' => [42];
        yield 'float' => [1.5];
        yield 'true' => [true];
        yield 'false' => [false];
        yield 'null' => [null];
        yield 'object' => [new \stdClass];
    }

    /**
     * assertValidCondition() accepts any condition that is not an array.
     *
     * @param  mixed  $condition
     * @return void
     */
    #[DataProvider('plainValueProvider')]
    public function testAssertValidConditionAcceptsPlainValue(mixed $condition): void
    {
        StatementValidator::assertValidCondition('tenant', $condition);

        $this->addToAssertionCount(1);
    }

    /**
     * assertValidCondition() refuses an empty operator map.
     *
     * @return void
     */
    public function testAssertValidConditionRefusesEmptyOperatorMap(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement condition \'tenant\' has no operators.');

        StatementValidator::assertValidCondition('tenant', []);
    }

    /**
     * assertValidCondition() refuses a list in place of an operator map.
     *
     * @return void
     */
    public function testAssertValidConditionRefusesNonStringOperator(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement condition \'tenant\' must map operator names to operands.');

        StatementValidator::assertValidCondition('tenant', ['org-1', 'org-2']);
    }

    /**
     * assertValidCondition() refuses a non-string operator that follows a valid
     * one.
     *
     * @return void
     */
    public function testAssertValidConditionRefusesNonStringOperatorAfterValidOne(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement condition \'level\' must map operator names to operands.');

        StatementValidator::assertValidCondition('level', ['gt' => 1, 0 => 5]);
    }

    /**
     * assertValidCondition() refuses an unknown operator, naming it.
     *
     * @return void
     */
    public function testAssertValidConditionRefusesUnknownOperator(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement condition \'tenant\' has an unknown operator \'equals\'.');

        StatementValidator::assertValidCondition('tenant', ['equals' => 'org-1']);
    }

    /**
     * assertValidCondition() refuses an unknown operator that follows a valid
     * one.
     *
     * @return void
     */
    public function testAssertValidConditionRefusesUnknownOperatorAfterValidOne(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement condition \'tenant\' has an unknown operator \'like\'.');

        StatementValidator::assertValidCondition('tenant', ['neq' => 'org-2', 'like' => 'org-*']);
    }

    /**
     * Data provider for operator maps with a malformed literal operand.
     *
     * @return \Generator<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function malformedOperandProvider(): iterable
    {
        yield 'in without array' => [['in' => 'org-1'], 'in'];
        yield 'not_in without array' => [['not_in' => 'org-1'], 'not_in'];
        yield 'cidr malformed' => [['cidr' => '10.0.0.0/33'], 'cidr'];
        yield 'cidr not a string' => [['cidr' => 10], 'cidr'];
        yield 'starts_with empty' => [['starts_with' => ''], 'starts_with'];
        yield 'ends_with not a string' => [['ends_with' => 5], 'ends_with'];
        yield 'string_like empty' => [['string_like' => ''], 'string_like'];
        yield 'before unparseable' => [['before' => 'not a time'], 'before'];
        yield 'after unparseable' => [['after' => 'not a time'], 'after'];
        yield 'between single bound' => [['between' => ['2026-01-01']], 'between'];
        yield 'gt non-numeric' => [['gt' => 'ten'], 'gt'];
        yield 'lte non-numeric' => [['lte' => [1]], 'lte'];
        yield 'bool unrecognised' => [['bool' => 'yes'], 'bool'];
    }

    /**
     * assertValidCondition() refuses a malformed literal operand, naming the
     * operator.
     *
     * @param  array<string, mixed>  $condition
     * @param  string  $operator
     * @return void
     */
    #[DataProvider('malformedOperandProvider')]
    public function testAssertValidConditionRefusesMalformedOperand(array $condition, string $operator): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Policy statement condition 'attr' has an invalid operand for operator '{$operator}'.");

        StatementValidator::assertValidCondition('attr', $condition);
    }

    /**
     * assertValidCondition() refuses a malformed operand that follows a valid
     * operator.
     *
     * @return void
     */
    public function testAssertValidConditionRefusesMalformedOperandAfterValidOne(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement condition \'level\' has an invalid operand for operator \'lt\'.');

        StatementValidator::assertValidCondition('level', ['gt' => 1, 'lt' => 'ten']);
    }

    /**
     * Data provider for operator maps whose operands are well formed.
     *
     * @return \Generator<string, array{0: array<string, mixed>}>
     */
    public static function validOperatorMapProvider(): iterable
    {
        yield 'eq' => [['eq' => 'org-1']];
        yield 'neq and in' => [['neq' => 'org-2', 'in' => ['org-1', 'org-3']]];
        yield 'null' => [['null' => true]];
        yield 'cidr literal' => [['cidr' => '10.0.0.0/8']];
        yield 'starts_with literal' => [['starts_with' => 'org-']];
        yield 'between literal' => [['between' => ['2026-01-01', '2026-12-31']]];
        yield 'numeric comparisons' => [['gt' => 1, 'gte' => 1.5, 'lt' => '10', 'lte' => 20]];
        yield 'bool literal' => [['bool' => 'true']];
        yield 'cidr interpolated' => [['cidr' => '${context.network}']];
        yield 'starts_with interpolated' => [['starts_with' => '${principal.id}']];
        yield 'before interpolated' => [['before' => '${context.deadline}']];
        yield 'after interpolated' => [['after' => '${context.start}']];
        yield 'gt interpolated' => [['gt' => '${context.minimum}']];
        yield 'bool interpolated' => [['bool' => '${context.flag}']];
        yield 'eq escaped reference' => [['eq' => '\${principal.id}']];
        yield 'starts_with escaped reference' => [['starts_with' => '\${x}']];
    }

    /**
     * assertValidCondition() accepts operator maps with well-formed literal
     * operands and with interpolated operands, which are only type-checked.
     *
     * @param  array<string, mixed>  $condition
     * @return void
     */
    #[DataProvider('validOperatorMapProvider')]
    public function testAssertValidConditionAcceptsValidOperatorMap(array $condition): void
    {
        StatementValidator::assertValidCondition('attr', $condition);

        $this->addToAssertionCount(1);
    }

    /**
     * assertValidCondition() refuses a plain value with a malformed `${…}`
     * reference.
     *
     * @return void
     */
    public function testAssertValidConditionRefusesMalformedReferenceInValue(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement condition \'tenant\' has a malformed ${…} reference.');

        StatementValidator::assertValidCondition('tenant', '${context.tenant-id}');
    }

    /**
     * assertValidCondition() refuses an operand with a malformed `${…}`
     * reference.
     *
     * @return void
     */
    public function testAssertValidConditionRefusesMalformedReferenceInOperand(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement condition \'owner\' has a malformed ${…} reference.');

        StatementValidator::assertValidCondition('owner', ['starts_with' => '${principal']);
    }

    /**
     * Data provider for conditionError() with every fault and the well-formed
     * conditions it accepts.
     *
     * @return \Generator<string, array{0: mixed, 1: string|null}>
     */
    public static function conditionErrorProvider(): iterable
    {
        $malformed = 'condition \'k\' has a malformed ${…} reference';

        yield 'plain value' => ['org-1', null];
        yield 'plain interpolated value' => ['${principal.id}', null];
        yield 'plain escaped value' => ['\${principal.id}', null];
        yield 'plain integer' => [42, null];
        yield 'plain null' => [null, null];
        yield 'well-formed operator map' => [['eq' => 'org-1', 'gt' => '${context.minimum}'], null];
        yield 'list operand not interpolated' => [['in' => ['${foo']], null];
        yield 'empty operator map' => [[], 'condition \'k\' has no operators'];
        yield 'list in place of map' => [['org-1', 'org-2'], 'condition \'k\' must map operator names to operands'];
        yield 'unknown operator' => [['x' => 'org-1'], 'condition \'k\' has an unknown operator \'x\''];
        yield 'invalid operand' => [['gt' => 'ten'], 'condition \'k\' has an invalid operand for operator \'gt\''];
        yield 'empty starts_with operand' => [['starts_with' => ''], 'condition \'k\' has an invalid operand for operator \'starts_with\''];
        yield 'malformed reference in value' => ['${context.tenant-id}', $malformed];
        yield 'empty reference in value' => ['${}', $malformed];
        yield 'digit-led reference in value' => ['${1x}', $malformed];
        yield 'unterminated reference in value' => ['${foo', $malformed];
        yield 'malformed reference in operand' => [['eq' => '${context.tenant-id}'], $malformed];
        yield 'malformed reference in string operand' => [['ends_with' => '${}'], $malformed];
        yield 'malformed reference beside a valid one' => [['eq' => '${principal.id}${1x}'], $malformed];
        yield 'malformed reference in numeric operand' => [['gt' => '${foo'], 'condition \'k\' has an invalid operand for operator \'gt\''];
    }

    /**
     * conditionError() returns the exact detail for each fault, and null for a
     * well-formed condition.
     *
     * @param  mixed  $condition
     * @param  string|null  $expected
     * @return void
     */
    #[DataProvider('conditionErrorProvider')]
    public function testConditionError(mixed $condition, ?string $expected): void
    {
        self::assertSame($expected, StatementValidator::conditionError('k', $condition));
    }

    /**
     * Data provider for operator maps with several faults, and the first one,
     * which is the fault reported.
     *
     * @return \Generator<string, array{0: array<array-key, mixed>, 1: string}>
     */
    public static function firstFaultProvider(): iterable
    {
        yield 'invalid operand before unknown operator' => [['gt' => 'ten', 'bogus' => 1], 'condition \'k\' has an invalid operand for operator \'gt\''];
        yield 'unknown operator before invalid operand' => [['bogus' => 1, 'gt' => 'ten'], 'condition \'k\' has an unknown operator \'bogus\''];
        yield 'non-string operator before unknown operator' => [[0 => 5, 'bogus' => 1], 'condition \'k\' must map operator names to operands'];
        yield 'malformed reference before invalid operand' => [['eq' => '${foo', 'gt' => 'ten'], 'condition \'k\' has a malformed ${…} reference'];
        yield 'invalid operand before malformed reference' => [['gt' => 'ten', 'eq' => '${foo'], 'condition \'k\' has an invalid operand for operator \'gt\''];
        yield 'first of several invalid operands' => [['gt' => 1, 'lt' => 'ten', 'bool' => 'yes'], 'condition \'k\' has an invalid operand for operator \'lt\''];
        yield 'unknown operator with malformed operand' => [['bogus' => '${foo'], 'condition \'k\' has an unknown operator \'bogus\''];
    }

    /**
     * conditionError() reports the first fault when several operators are bad.
     *
     * @param  array<array-key, mixed>  $condition
     * @param  string  $expected
     * @return void
     */
    #[DataProvider('firstFaultProvider')]
    public function testConditionErrorReportsFirstFault(array $condition, string $expected): void
    {
        self::assertSame($expected, StatementValidator::conditionError('k', $condition));
    }

    /**
     * Data provider for resource patterns without a malformed reference.
     *
     * @return \Generator<string, array{0: string}>
     */
    public static function wellFormedResourceProvider(): iterable
    {
        yield 'wildcard' => ['*'];
        yield 'empty' => [''];
        yield 'literal' => ['document:1'];
        yield 'glob' => ['document:*'];
        yield 'reference' => ['document:${principal.id}'];
        yield 'several references' => ['tenant:${principal.tenant_id}/document:${resource.id}'];
        yield 'escaped reference' => ['document:\${principal.id}'];
        yield 'escaped malformed reference' => ['document:\${tenant-id}'];
        yield 'escaped beside reference' => ['\${x}:${principal.id}'];
        yield 'dollar without brace' => ['price:$5'];
    }

    /**
     * assertValidResource() accepts well-formed and escaped references.
     *
     * @param  string  $pattern
     * @return void
     */
    #[DataProvider('wellFormedResourceProvider')]
    public function testAssertValidResourceAcceptsWellFormedPattern(string $pattern): void
    {
        StatementValidator::assertValidResource($pattern);

        $this->addToAssertionCount(1);
    }

    /**
     * Data provider for resource patterns with a malformed reference.
     *
     * @return \Generator<string, array{0: string}>
     */
    public static function malformedResourceProvider(): iterable
    {
        yield 'hyphenated key' => ['document:${context.tenant-id}'];
        yield 'empty reference' => ['document:${}'];
        yield 'digit-led reference' => ['document:${1x}'];
        yield 'unterminated reference' => ['document:${foo'];
        yield 'malformed beside well-formed' => ['${principal.id}:${1x}'];
    }

    /**
     * assertValidResource() refuses a malformed reference, quoting the pattern.
     *
     * @param  string  $pattern
     * @return void
     */
    #[DataProvider('malformedResourceProvider')]
    public function testAssertValidResourceRefusesMalformedReference(string $pattern): void
    {
        try {
            StatementValidator::assertValidResource($pattern);
            self::fail('Expected an InvalidArgumentException.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame("Policy statement resource pattern '{$pattern}' has a malformed \${…} reference.", $exception->getMessage());
        }
    }

    /**
     * conditionErrors() maps each malformed condition to its fault, keyed by
     * the condition's key, and leaves well-formed conditions out.
     *
     * @return void
     */
    public function testConditionErrorsMapsOnlyMalformedConditions(): void
    {
        $errors = StatementValidator::conditionErrors([
            'tenant' => ['eq' => 'org-1'],
            'region' => 'eu',
            'empty'  => [],
            7        => 'x',
            'op'     => ['bogus' => 1],
        ]);

        self::assertSame([
            'empty' => 'condition \'empty\' has no operators',
            7       => 'a condition key is not a string',
            'op'    => 'condition \'op\' has an unknown operator \'bogus\'',
        ], $errors);
    }

    /**
     * conditionErrors() returns an empty map for an empty or well-formed
     * condition map.
     *
     * @return void
     */
    public function testConditionErrorsIsEmptyForWellFormedConditions(): void
    {
        self::assertSame([], StatementValidator::conditionErrors([]));
        self::assertSame([], StatementValidator::conditionErrors(['tenant' => ['eq' => 'org-1'], 'flag' => true]));
    }
}
