<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * Coverage for the three operand shapes `Statement::interpolateOperands`
 * must handle when an interpolator is supplied:
 *
 * - A plain string operand is interpolated directly.
 * - An array operand with a non-string value passes the non-string
 *   through unchanged (integers, booleans, and null operands that
 *   consumers occasionally use for `null` identity checks).
 * - A non-string, non-array operand (scalar, object, null) is
 *   returned verbatim.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Statement::class)]
final class StatementInterpolationBranchesTest extends TestCase
{
    /**
     * A scalar string condition operand is interpolated directly —
     * the payload is the operand, not an operator map — and compared
     * by identity against the context value.
     *
     * @return void
     */
    public function testStringOperandIsInterpolatedInPlace(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['tenant' => '${principal.id}'],
        ]);

        $principal = new class {
            /**
             * @param  string  $key
             * @return string
             */
            public function getAttribute(string $key): string
            {
                return $key === 'id' ? 'org-7' : '';
            }
        };

        self::assertTrue($statement->evaluateConditions(
            ['tenant' => 'org-7'],
            new ContextInterpolator,
            $principal,
        ));

        self::assertFalse($statement->evaluateConditions(
            ['tenant' => 'org-9'],
            new ContextInterpolator,
            $principal,
        ));
    }

    /**
     * An array operand that contains a non-string entry passes the
     * non-string through unchanged — e.g. a boolean flag or an
     * integer bound against the context.
     *
     * @return void
     */
    public function testNonStringEntryInArrayOperandIsUnchanged(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['flag' => ['eq' => true]],
        ]);

        self::assertTrue($statement->evaluateConditions(
            ['flag' => true],
            new ContextInterpolator,
            null,
        ));
    }

    /**
     * A non-string, non-array operand (boolean) passes through
     * `interpolateOperands` verbatim and is compared by identity
     * against the context value.
     *
     * @return void
     */
    public function testScalarOperandPassesThroughInterpolation(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['flag' => true],
        ]);

        self::assertTrue($statement->evaluateConditions(
            ['flag' => true],
            new ContextInterpolator,
            null,
        ));

        self::assertFalse($statement->evaluateConditions(
            ['flag' => false],
            new ContextInterpolator,
            null,
        ));
    }
}
