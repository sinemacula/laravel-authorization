<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\HeldLifetime;
use SineMacula\Laravel\Authorization\Administration\HeldLifetimes;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `HeldLifetimes`: how long a subject holds a right or a
 * policy, each read once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HeldLifetimes::class)]
final class HeldLifetimesTest extends TestCase
{
    /**
     * Each lifetime is the one `HeldLifetime` reads, a right's and a policy's
     * kept apart even under the same name, and each is read once, a lifetime of
     * none included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachLifetimeIsReadOnce(): void
    {
        $user   = StubIdentity::query()->create(['id' => 'user-1']);
        $policy = Policy::query()->create(['name' => 'reader', 'document' => ['statements' => []]]);
        $grants = app(GrantService::class);

        $grants->grantPermission($user, Permission::query()->create(['name' => 'posts:read']), Carbon::now()->addDay());
        $grants->attachPolicy($user, $policy);

        $subject   = new Subject($user, $user);
        $lifetimes = new HeldLifetimes($subject);

        self::assertSame(HeldLifetime::of($subject, 'posts:read'), $lifetimes->of('posts:read'));
        self::assertSame(\PHP_INT_MAX, $lifetimes->ofPolicy($policy->getKey()));
        self::assertNull($lifetimes->of('posts:edit'));
        self::assertNull($lifetimes->of($policy->getKey()));

        DB::flushQueryLog();
        DB::enableQueryLog();

        $lifetimes->of('posts:read');
        $lifetimes->of('posts:edit');
        $lifetimes->ofPolicy($policy->getKey());

        $queries = \count(DB::getQueryLog());

        DB::disableQueryLog();

        self::assertSame(0, $queries);
    }
}
