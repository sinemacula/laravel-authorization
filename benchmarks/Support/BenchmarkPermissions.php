<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;

/**
 * Bench permission provider — declares the fixture permissions and the action
 * the benchmark policy allows, so the policy validator accepts the benchmark
 * policy's actions. Kept as a named class so the container can resolve it from
 * `authorization.permission_providers`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BenchmarkPermissions implements PermissionProvider
{
    /** @var string The action the benchmark policy allows and no role grants. */
    public const string POLICY_ACTION = 'reports:read';

    /**
     * Return the fixture permissions and the policy-only action.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     */
    #[\Override]
    public function permissions(): array
    {
        $names = [...BenchmarkFixtures::permissionNames(), self::POLICY_ACTION];

        return \array_map(static fn (string $name): PermissionDefinition => new PermissionDefinition($name), $names);
    }
}
