<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Policy;

/**
 * Performance budget for `Policy::fromArray()`.
 *
 * The parse path turns serialised policy documents into immutable
 * `Policy` value objects on every cache-miss boundary — cold-start
 * hydration, corrupt-entry recovery, and the persistent tier's cold
 * read. A regression in parse throughput compounds across every
 * cache miss in a request, so the suite codifies a loose wall-clock
 * budget to catch runaway allocations or accidental reflection use
 * in the parse path.
 *
 * Budget is set generously — the PHPBench suite tracks the actual
 * micro-trend, this test is the safety net.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Policy::class)]
#[CoversClass(PolicyObserver::class)]
final class PolicyParseBudgetTest extends TestCase
{
    /**
     * Parsing a 20-statement policy document (each with 5 actions,
     * 3 resources, and 2 conditions) 1,000 times must complete in
     * under one second on the reference machine.
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

        self::assertLessThan(
            1.0,
            $elapsed,
            "Policy::fromArray() parse budget exceeded ({$elapsed}s for 1,000 iterations).",
        );
    }

    /**
     * Build the fixture document — kept here rather than in a
     * shared helper so the performance suite has no runtime
     * dependency on the benchmark-support tree and stays
     * self-contained.
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
                    'StringEquals'    => ['context:tenant' => "tenant_{$i}"],
                    'NumericLessThan' => ['context:rank' => 100],
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
