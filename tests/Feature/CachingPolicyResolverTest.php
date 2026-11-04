<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\CachingPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `CachingPolicyResolver`, whose cached entries are bounded
 * by the nearest expiry among the policies a principal attaches itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(CachingPolicyResolver::class)]
final class CachingPolicyResolverTest extends TestCase
{
    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A policy attached until 12:05 allows the action until then and stops
     * allowing it at 12:05 within the same job, for the same identity instance.
     *
     * @return void
     */
    public function testExpiringPolicyLapsesWithinOneJob(): void
    {
        $user = $this->identityWithPolicyUntil('2026-07-01 12:05:00');

        self::assertTrue(Authorization::for($user)->can('posts:read', 'posts/1'));

        Carbon::setTestNow('2026-07-01 12:04:59');

        self::assertTrue(Authorization::for($user)->can('posts:read', 'posts/1'));

        Carbon::setTestNow('2026-07-01 12:05:00');

        self::assertFalse(Authorization::for($user)->can('posts:read', 'posts/1'));
    }

    /**
     * With a persistent store configured, the stored entry is bounded by the
     * policy's expiry too, so the next job does not read the lapsed policy back
     * from the store.
     *
     * @return void
     */
    public function testExpiringPolicyLapsesFromThePersistentStore(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 'array');

        (new AuthorizationServiceProvider($this->app))->register();

        $user = $this->identityWithPolicyUntil('2026-07-01 12:05:00');

        self::assertTrue(Authorization::for($user)->can('posts:read', 'posts/1'));

        Carbon::setTestNow('2026-07-01 12:05:00');
        $this->app?->forgetScopedInstances();

        self::assertFalse(Authorization::for($user->fresh() ?? $user)->can('posts:read', 'posts/1'));
    }

    /**
     * A live entry is served without reading the principal's policies again.
     *
     * @return void
     */
    public function testLiveEntryDoesNotReloadThePolicies(): void
    {
        $user     = $this->identityWithPolicyUntil('2026-07-01 13:00:00');
        $resolver = $this->resolver();

        self::assertCount(1, $resolver->policiesFor($user));

        DB::flushQueryLog();
        DB::enableQueryLog();

        Carbon::setTestNow('2026-07-01 12:30:00');

        self::assertCount(1, $resolver->policiesFor($user));
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * A principal that cannot attach policies is resolved and cached without an
     * expiry bound.
     *
     * @return void
     */
    public function testPrincipalWithoutPoliciesOfItsOwnIsCached(): void
    {
        $calls    = 0;
        $resolver = new CachingPolicyResolver(
            inner: new class ($calls) implements PolicyResolver {
                /**
                 * Create a resolver that counts its calls.
                 *
                 * @param  int  $calls
                 */
                public function __construct(

                    /** Number of times the resolver has run. */
                    private int &$calls,
                ) {}

                /**
                 * Count the call and resolve no policies.
                 *
                 * @param  object  $principal
                 * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
                 */
                #[\Override]
                public function policiesFor(object $principal): array
                {
                    $this->calls++;

                    return [];
                }
            },
            cache: new ResolutionCache,
        );

        $principal = new \stdClass;

        self::assertSame([], $resolver->policiesFor($principal));
        self::assertSame([], $resolver->policiesFor($principal));
        self::assertSame(1, $calls);
    }

    /**
     * Build a caching resolver over the default resolver and a fresh cache.
     *
     * @return \SineMacula\Laravel\Authorization\Resolvers\CachingPolicyResolver
     */
    private function resolver(): CachingPolicyResolver
    {
        return new CachingPolicyResolver(inner: new DefaultPolicyResolver, cache: new ResolutionCache);
    }

    /**
     * Create an identity, at 12:00, holding a policy that allows reading posts
     * until the given instant.
     *
     * @param  string  $expiresAt
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function identityWithPolicyUntil(string $expiresAt): StubIdentity
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'temporary-reader',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['*']],
                ],
            ],
        ]), Carbon::parse($expiresAt));

        return $user;
    }
}
