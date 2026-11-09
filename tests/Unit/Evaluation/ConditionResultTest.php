<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ConditionResult;
use SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome;

/**
 * Unit tests for the condition result value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConditionResult::class)]
final class ConditionResultTest extends TestCase
{
    /**
     * A result defaults to a test without `_if_exists`, of a key present, with
     * no reference unresolved.
     *
     * @return void
     */
    public function testDefaults(): void
    {
        $result = new ConditionResult('input.team', 'eq', ConditionOutcome::HELD);

        self::assertSame('input.team', $result->key);
        self::assertSame('eq', $result->operator);
        self::assertSame(ConditionOutcome::HELD, $result->outcome);
        self::assertFalse($result->isOptional);
        self::assertFalse($result->isMissing);
        self::assertSame([], $result->unresolved);
    }

    /**
     * toArray() renders every field in the schema's names.
     *
     * @return void
     */
    public function testToArray(): void
    {
        $result = new ConditionResult('input.team', 'eq', ConditionOutcome::UNRESOLVED, true, true, ['input.owner']);

        self::assertSame(
            ['key' => 'input.team', 'operator' => 'eq', 'if_exists' => true, 'outcome' => 'unresolved', 'missing' => true, 'unresolved' => ['input.owner']],
            $result->toArray(),
        );
    }
}
