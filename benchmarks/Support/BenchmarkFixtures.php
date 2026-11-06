<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use SineMacula\Laravel\Authorization\Evaluation\Policy;

/**
 * Static fixture factory shared across every benchmark class.
 *
 * Keeps the shape of fixtures consistent so cross-benchmark comparisons
 * (PolicyParse vs PolicyEvaluator vs Manager) measure the same document profile
 * and any drift between them reflects genuine hot-path change — not accidental
 * fixture skew.
 *
 * The factories here deliberately return primitive arrays (for the parse path)
 * or fully hydrated `Policy` value objects (for the evaluate path). No
 * database, no container, no Eloquent — each bench that needs those wires them
 * up in its own base class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class BenchmarkFixtures
{
    /**
     * Build a realistic policy document array — 20 statements, each with 5
     * actions, 3 resources, and 2 conditions. Matches the parse-budget
     * performance test so both surfaces measure the same document weight.
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
                    'eq' => ['tenant' => "tenant_{$i}"],
                    'lt' => ['rank' => 100],
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
     * Hydrate the benchmark policy document into a `Policy` value object.
     * Useful for benches that exercise the evaluator, not the parser.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    public static function policy(): Policy
    {
        return Policy::fromArray(self::policyDocument());
    }

    /**
     * A small list of permission names used by the RBAC and manager benches.
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

    /**
     * A realistic interpolation context — matches the shape callers pass
     * through `can()`: a principal stand-in under `user`, request metadata, and
     * a tenant scalar. Paired with the `interpolationPattern()` fixture so the
     * 10-token parse path hits plain keys, dot-notation keys, and resource
     * namespaces.
     *
     * @return array<string, mixed>
     */
    public static function interpolationContext(): array
    {
        return [
            'tenant'  => 'tenant-99',
            'request' => [
                'ip'         => '10.0.0.42',
                'method'     => 'POST',
                'path'       => '/admin/posts/99',
                'country'    => 'US',
                'referrer'   => 'https://example.test/dashboard',
                'user_agent' => 'Mozilla/5.0',
            ],
            'environment' => 'production',
        ];
    }

    /**
     * A 10-token interpolation pattern blending principal, resource, and
     * dot-notation context lookups. Used by the `ContextInterpolator`
     * benchmark.
     *
     * @return string
     */
    public static function interpolationPattern(): string
    {
        return '${principal.id}:${principal.type}:${resource.type}:${resource.id}'
            . ':${context.tenant}:${context.request.ip}:${context.request.method}'
            . ':${context.request.path}:${context.request.country}:${context.environment}';
    }

    /**
     * A 20-token interpolation pattern — doubles the 10-token fixture so the
     * performance-budget test has a higher-weight measurement to run against
     * without drifting from the bench fixture shape.
     *
     * @return string
     */
    public static function interpolationPatternWide(): string
    {
        return self::interpolationPattern() . ':' . self::interpolationPattern();
    }

    /**
     * Full 20-operator condition map covering every operator of
     * `ConditionEvaluator` — string ops, numeric ops, temporal ops, set ops,
     * boolean, null, IP range and multi-valued checks. Used by the
     * condition-evaluation bench and its matching budget test so both surfaces
     * measure the same operator chain.
     *
     * @return array<string, mixed>
     */
    public static function conditionChain(): array
    {
        return [
            'eq'            => ['tenant' => 'tenant-99'],
            'neq'           => ['role' => 'guest'],
            'in'            => ['country' => ['US', 'GB', 'CA']],
            'not_in'        => ['blocklist' => ['blocked', 'banned']],
            'starts_with'   => ['path' => '/admin'],
            'ends_with'     => ['file' => '.json'],
            'like'          => ['agent' => 'Mozilla/*'],
            'gt'            => ['age' => 17],
            'gte'           => ['quota' => 0],
            'lt'            => ['strikes' => 3],
            'lte'           => ['priority' => 10],
            'before'        => ['scheduled_at' => '2099-01-01T00:00:00Z'],
            'after'         => ['created_at' => '2000-01-01T00:00:00Z'],
            'between'       => ['window' => ['2000-01-01T00:00:00Z', '2099-01-01T00:00:00Z']],
            'bool'          => ['verified' => true],
            'null'          => ['deleted_at' => true, 'email' => false],
            'ip_in'         => ['ip' => '10.0.0.0/8'],
            'ip_not_in'     => ['ip' => ['192.168.0.0/16', '2001:db8::/32']],
            'any_value_in'  => ['groups' => ['admins', 'editors']],
            'all_values_in' => ['scopes' => ['posts:read', 'posts:write', 'posts:delete']],
        ];
    }

    /**
     * Context matching the 20-operator `conditionChain()` fixture — every key
     * resolves to a value that makes its operator pass.
     *
     * @return array<string, mixed>
     */
    public static function conditionContext(): array
    {
        return [
            'tenant'       => 'tenant-99',
            'role'         => 'member',
            'country'      => 'US',
            'blocklist'    => 'allowed',
            'ip'           => '10.0.0.42',
            'path'         => '/admin/posts',
            'file'         => 'report.json',
            'scheduled_at' => '2026-06-01T00:00:00Z',
            'created_at'   => '2026-01-01T00:00:00Z',
            'window'       => '2026-06-01T00:00:00Z',
            'agent'        => 'Mozilla/5.0',
            'deleted_at'   => null,
            'email'        => 'alice@example.test',
            'age'          => 42,
            'quota'        => 10,
            'strikes'      => 0,
            'priority'     => 5,
            'verified'     => true,
            'groups'       => ['members', 'editors'],
            'scopes'       => ['posts:read', 'posts:write'],
        ];
    }
}
