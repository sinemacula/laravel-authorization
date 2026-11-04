<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Models\Policy;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `HasPolicies::secondsUntilPolicyExpiry()`, which bounds the
 * caching policy resolver's entries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(HasPolicies::class)]
final class HasPoliciesTest extends TestCase
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
     * The nearest expiry among the attached policies bounds the result, and
     * policies attached forever do not.
     *
     * @return void
     */
    public function testReturnsSecondsUntilTheNearestAttachedPolicyLapses(): void
    {
        $user = $this->identity();

        self::assertNull($user->secondsUntilPolicyExpiry());

        $user->attachPolicy($this->policy('forever'));
        $user->attachPolicy($this->policy('later'), Carbon::parse('2026-07-01 13:00:00'));
        $user->attachPolicy($this->policy('sooner'), Carbon::parse('2026-07-01 12:05:00'));

        self::assertSame(300, $user->secondsUntilPolicyExpiry());
    }

    /**
     * The loaded attachments are reused unless a reload is asked for, which
     * reads them afresh.
     *
     * @return void
     */
    public function testReloadReadsTheAttachmentsAfresh(): void
    {
        $user = $this->identity();
        $user->attachPolicy($this->policy('sooner'), Carbon::parse('2026-07-01 12:05:00'));

        self::assertSame(300, $user->secondsUntilPolicyExpiry());

        DB::table('authorizable_policies')->update(['expires_at' => Carbon::parse('2026-07-01 12:10:00')]);

        self::assertSame(300, $user->secondsUntilPolicyExpiry());
        self::assertSame(600, $user->secondsUntilPolicyExpiry(true));
    }

    /**
     * Create an identity at 12:00.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function identity(): StubIdentity
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        return StubIdentity::create(['id' => (string) Str::uuid()]);
    }

    /**
     * Create a policy that allows reading posts.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private function policy(string $name): Policy
    {
        return Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => $name,
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['*']],
                ],
            ],
        ]);
    }
}
