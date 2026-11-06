<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\BoundaryException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Support\PolicyBoundaries;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the rule that a policy in use as a permission boundary is
 * never deleted from under the grantees it bounds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PolicyBoundaries::class)]
final class PolicyBoundariesTest extends TestCase
{
    use ActsAsTenant;

    /**
     * A policy bounding no one may be deleted, and a policy not yet saved
     * bounds no one without a query.
     *
     * @return void
     */
    public function testAPolicyBoundingNoOneIsDeletable(): void
    {
        $policy = self::cap('cap');

        PolicyBoundaries::assertDeletable($policy);

        self::assertFalse(PolicyBoundaries::isBoundary($policy));

        DB::enableQueryLog();
        DB::flushQueryLog();

        PolicyBoundaries::assertDeletable(new Policy(['name' => 'unsaved']));

        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * A policy in use as a boundary is refused, naming each grantee it bounds
     * once, in order of type then key, however many scopes it bounds it in, and
     * telling apart grantees of one key and different types.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyInUseAsABoundaryIsRefused(): void
    {
        $policy = self::cap('cap');
        $tenant = self::createTenant('tenant-a');

        self::service()->set(new Reference('user', 'user-2'), $policy);
        self::service()->set(new Reference('user', 'user-1'), $policy);
        self::service()->set(new Reference('user', 'user-1'), $policy, $tenant);
        self::service()->set(new Reference('team', 'user-1'), $policy);

        self::assertTrue(PolicyBoundaries::isBoundary($policy));

        try {
            PolicyBoundaries::assertDeletable($policy);
            self::fail('The deletion was not refused.');
        } catch (BoundaryException $exception) {
            self::assertSame('cap', $exception->getPolicyName());
            self::assertEquals([new Reference('team', 'user-1'), new Reference('user', 'user-1'), new Reference('user', 'user-2')], $exception->getGrantees());
        }
    }

    /**
     * Deleting a policy in use as a boundary is refused and deletes nothing;
     * once every boundary it is has been removed, it is deleted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAPolicyInUseIsRefusedUntilItsBoundariesAreRemoved(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::cap('cap');

        self::service()->set($user, $policy);

        try {
            $policy->delete();
            self::fail('The deletion was not refused.');
        } catch (BoundaryException $exception) {
            self::assertStringContainsString("Policy 'cap' is the boundary of {$user->getMorphClass()}:user-1", $exception->getMessage());
        }

        self::assertTrue(Policy::query()->whereKey($policy->getKey())->exists());
        self::assertSame(1, DB::table('authorizable_boundaries')->count());

        self::service()->remove($user);

        self::assertTrue($policy->delete());
        self::assertFalse(Policy::query()->whereKey($policy->getKey())->exists());
    }

    /**
     * Return the boundary service, as the container binds it.
     *
     * @return \SineMacula\Laravel\Authorization\Services\BoundaryService
     */
    private static function service(): BoundaryService
    {
        $service = BoundaryService::instance();

        self::assertInstanceOf(BoundaryService::class, $service);

        return $service;
    }

    /**
     * Create a boundary policy allowing `posts:read`.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function cap(string $name): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);
    }
}
