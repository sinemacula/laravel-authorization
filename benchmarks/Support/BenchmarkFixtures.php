<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use SineMacula\Laravel\Authorization\Evaluation\Policy;

/**
 * Static fixture factory shared across every benchmark class.
 *
 * Keeps the shape of fixtures consistent so cross-benchmark
 * comparisons (PolicyParse vs PolicyEvaluator vs Manager) measure the
 * same document profile and any drift between them reflects genuine
 * hot-path change — not accidental fixture skew.
 *
 * The factories here deliberately return primitive arrays (for the
 * parse path) or fully hydrated `Policy` value objects (for the
 * evaluate path). No database, no container, no Eloquent — each
 * bench that needs those wires them up in its own base class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BenchmarkFixtures
{
    /**
     * Build a realistic policy document array — 20 statements, each
     * with 5 actions, 3 resources, and 2 conditions. Matches the
     * parse-budget performance test so both surfaces measure the
     * same document weight.
     *
     * @return array<string, mixed>
     */
    public static function policyDocument(): array
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

    /**
     * Hydrate the benchmark policy document into a `Policy` value
     * object. Useful for benches that exercise the evaluator, not
     * the parser.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    public static function policy(): Policy
    {
        return Policy::fromArray(self::policyDocument());
    }

    /**
     * A small list of permission names used by the RBAC and manager
     * benches.
     *
     * @return array<int, string>
     */
    public static function permissionNames(): array
    {
        return [
            'posts:create',
            'posts:read',
            'posts:update',
            'posts:delete',
            'posts:publish',
        ];
    }

    /**
     * Stable role name used across benches so `Role::resolveByName()`
     * measurements run against a predictable fixture.
     *
     * @return string
     */
    public static function roleName(): string
    {
        return 'benchmark-role';
    }
}
