<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Observers\PolicyObserver;
use Tests\Concerns\MeasuresTime;

/**
 * Performance budget for `Policy::fromArray()`.
 *
 * The parse path turns serialised policy documents into immutable `Policy`
 * value objects on every cache-miss boundary — cold-start hydration,
 * corrupt-entry recovery, and the persistent tier's cold read. A regression in
 * parse throughput compounds across every cache miss in a request, so the suite
 * codifies a loose wall-clock budget to catch runaway allocations or accidental
 * reflection use in the parse path.
 *
 * Budget is set generously — the PHPBench suite tracks the actual micro-trend,
 * this test is the safety net. The policy language checks every operand,
 * address and pattern as it parses, and each statement notes the `${…}`
 * references it may read, so the budget allows one and a half seconds, which
 * still catches a parse path that has doubled. The budget is enforced outside
 * coverage runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Policy::class)]
#[CoversClass(PolicyObserver::class)]
final class PolicyParseBudgetTest extends TestCase
{
    use MeasuresTime;

    /**
     * Parsing a 20-statement policy document (each with 5 actions, 3 resources,
     * and 2 conditions) 1,000 times must complete in under one and a half
     * seconds.
     *
     * @return void
     */
    public function testCanParseRealisticDocumentQuickly(): void
    {
        $document = self::buildRealisticDocument();

        $start = \microtime(true);

        for ($i = 0; $i < 1000; $i++) {
            Policy::fromArray($document);
        }

        $elapsed = \microtime(true) - $start;

        $this->assertWithinBudget(
            1.5,
            $elapsed,
            "Policy::fromArray() parse budget exceeded ({$elapsed}s for 1,000 iterations).",
        );
    }

    /**
     * Build the fixture document — kept here rather than in a shared helper so
     * the performance suite has no runtime dependency on the benchmark-support
     * tree and stays self-contained.
     *
     * @return array<string, mixed>
     */
    private static function buildRealisticDocument(): array
    {
        $statements = [];

        for ($i = 0; $i < 20; $i++) {
            $statements[] = [
                'effect'  => $i % 2 === 0 ? 'allow' : 'deny',
                'actions' => [
                    "posts:action_{$i}_a",
                    "posts:action_{$i}_b",
                    "posts:action_{$i}_c",
                    "posts:action_{$i}_d",
                    "posts:action_{$i}_e",
                ],
                'resources' => [
                    "posts:resource_{$i}_a",
                    "posts:resource_{$i}_b",
                    "posts:resource_{$i}_c",
                ],
                'conditions' => [
                    'eq' => ['input.tenant' => "tenant_{$i}"],
                    'lt' => ['input.rank' => 100],
                ],
            ];
        }

        return [
            'name'       => 'benchmark-policy',
            'version'    => 1,
            'statements' => $statements,
        ];
    }
}
