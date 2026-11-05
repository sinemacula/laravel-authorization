<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use Psr\Log\AbstractLogger;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Models\Policy;
use Tests\Concerns\ChecksGrantExpiry;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the policy hydration in `HasPolicies::getPolicies()` and
 * for `HasPolicies::secondsUntilPolicyExpiry()`, which bounds the caching
 * policy resolver's entries.
 *
 * Every attached row hydrates into an evaluation policy. A row whose document
 * cannot be read is logged as a warning on the `authorization` channel and its
 * exception is rethrown, so the caller denies the check rather than evaluating
 * the remaining policies without it.
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
    use ChecksGrantExpiry;

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
     * An attachment records when it was made and when it last changed.
     *
     * @return void
     */
    public function testAttachmentKeepsItsTimestamps(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $user   = StubIdentity::create(['id' => (string) Str::uuid()]);
        $policy = Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);

        $user->attachPolicy($policy);

        Carbon::setTestNow('2026-07-01 12:30:00');

        $user->attachPolicy($policy, Carbon::parse('2026-07-01 14:00:00'));

        $row = DB::table('authorizable_policies')->sole();

        self::assertSame('2026-07-01 12:00:00', Carbon::parse((string) $row->created_at)->format('Y-m-d H:i:s'));
        self::assertSame('2026-07-01 12:30:00', Carbon::parse((string) $row->updated_at)->format('Y-m-d H:i:s'));
    }

    /**
     * Every attached row with a valid document hydrates into an evaluation
     * policy named after the row.
     *
     * @return void
     */
    public function testGetPoliciesHydratesEveryAttachedRow(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        foreach (['first', 'second'] as $name) {
            $user->attachPolicy(Policy::create([
                'id'       => (string) Str::uuid(),
                'name'     => $name,
                'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:' . $name]]]],
            ]));
        }

        $names = \array_map(static fn ($policy): string => $policy->name, $user->getPolicies());
        \sort($names);

        self::assertSame(['first', 'second'], $names);
    }

    /**
     * An identity without attached policies hydrates to an empty list.
     *
     * @return void
     */
    public function testGetPoliciesReturnsEmptyListWithoutAttachedRows(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        self::assertSame([], $user->getPolicies());
    }

    /**
     * A malformed row is logged as a warning on the `authorization` channel and
     * its exception is rethrown, even when a valid row is also attached.
     *
     * @return void
     */
    public function testGetPoliciesLogsAndRethrowsForMalformedRow(): void
    {
        $logger = self::recordingLogger();
        $this->app->instance('log', $logger); // @phpstan-ignore method.nonObject

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'valid',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:create']]]],
        ]));

        $badId = (string) Str::uuid();
        DB::table('policies')->insert([
            'id'         => $badId,
            'name'       => 'malformed',
            'document'   => \json_encode(['statements' => [['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => []]]]),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('authorizable_policies')->insert([
            'policy_id'         => $badId,
            'authorizable_type' => $user->getMorphClass(),
            'authorizable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
        ]);

        $reason = 'Invalid policy document \'malformed\': Policy statement resources must not be empty; omit the key to cover every resource.';

        try {
            $user->fresh()?->getPolicies();
            self::fail('getPolicies() should rethrow for a malformed row.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertSame('malformed', $exception->getPolicyName());
            self::assertSame($reason, $exception->getMessage());
        }

        // A logger that is not Laravel's log manager is written to directly;
        // channel selection is covered by AuthorizationLogTest.
        self::assertSame([], $logger->channels);
        self::assertSame([
            [
                'message' => "Authorization: malformed policy '{$badId}' denies every check for its holder: {$reason}",
                'context' => [
                    'policy_id'   => $badId,
                    'policy_name' => 'malformed',
                    'reason'      => $reason,
                ],
            ],
        ], $logger->warnings);
    }

    /**
     * A malformed row without a name is logged with an empty policy name and
     * its key cast to a string.
     *
     * @return void
     */
    public function testGetPoliciesLogsUnnamedRowWithEmptyNameAndStringKey(): void
    {
        $logger = self::recordingLogger();
        $this->app->instance('log', $logger); // @phpstan-ignore method.nonObject

        $policy = new Policy;
        $policy->setRawAttributes(['id' => 42, 'document' => 'not-a-json-document']);

        $user = new StubIdentity;
        $user->setRelation('policies', new Collection([$policy]));

        $reason = 'Invalid policy document \'[unnamed]\': policy document must be a JSON object or array.';

        try {
            $user->getPolicies();
            self::fail('getPolicies() should rethrow for an unreadable row.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertSame($reason, $exception->getMessage());
        }

        self::assertSame([
            [
                'message' => "Authorization: malformed policy '42' denies every check for its holder: {$reason}",
                'context' => [
                    'policy_id'   => '42',
                    'policy_name' => '',
                    'reason'      => $reason,
                ],
            ],
        ], $logger->warnings);
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
     * The write methods go through the grant service: attaching what is
     * attached dispatches nothing, and each returns the identity.
     *
     * @return void
     */
    public function testWritesGoThroughTheGrantService(): void
    {
        Event::fake([PolicyAttached::class, PolicyDetached::class]);

        $user    = $this->identity();
        $policy  = $this->policy('readers');
        $expires = Carbon::parse('2026-07-02 12:00:00', 'UTC');

        self::assertSame($user, $user->attachPolicy($policy, $expires));
        self::assertSame($user, $user->attachPolicy($policy, $expires));
        self::assertSame('2026-07-02 12:00:00', DB::table('authorizable_policies')->value('expires_at'));
        self::assertSame($user, $user->syncPolicies([$policy]));
        Event::assertDispatchedTimes(PolicyAttached::class, 1);

        self::assertSame($user, $user->detachPolicy($policy));
        self::assertSame($user, $user->detachPolicy($policy));
        self::assertSame(0, DB::table('authorizable_policies')->count());
        Event::assertDispatchedTimes(PolicyDetached::class, 1);
    }

    /**
     * A sync refuses anything that is not a saved policy, and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncRefusesAnythingButAPolicy(): void
    {
        $user   = $this->identity();
        $policy = $this->policy('readers');

        $user->attachPolicy($policy);

        try {
            $user->syncPolicies([$user]); // @phpstan-ignore argument.type
            self::fail('The identity was not refused.');
        } catch (InvalidGrantTargetException $exception) {
            self::assertSame('policy', $exception->getKind());
        }

        self::assertSame([$policy->id], DB::table('authorizable_policies')->pluck('policy_id')->all());
    }

    /**
     * Return the grant table the expiry check reads.
     *
     * @return string
     */
    #[\Override]
    protected static function grantTable(): string
    {
        return 'authorizable_policies';
    }

    /**
     * Return the event a change of the grant's expiry dispatches.
     *
     * @return class-string
     */
    #[\Override]
    protected static function expiryChangedEvent(): string
    {
        return PolicyExpiryChanged::class;
    }

    /**
     * Return the name of the row the expiry check grants.
     *
     * @return string
     */
    #[\Override]
    protected static function grantedName(): string
    {
        return 'readers';
    }

    /**
     * Grant the identity the checked row until the given instant.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \DateTimeInterface  $expiresAt
     * @return void
     */
    #[\Override]
    protected function grantUntil(StubIdentity $identity, \DateTimeInterface $expiresAt): void
    {
        $identity->attachPolicy(Policy::query()->firstOrCreate(['name' => 'readers'], ['document' => ['version' => 1, 'statements' => []]]), $expiresAt);
    }

    /**
     * Return the names of the rows the identity holds.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @return list<string>
     */
    #[\Override]
    protected function heldNames(StubIdentity $identity): array
    {
        /** @var list<string> */
        return $identity->policies->pluck('name')->all();
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

    /**
     * Build a logger that records the channels it is asked for and every
     * warning it receives.
     *
     * @return object{channels: list<string>, warnings: list<array{message: string, context: array<mixed>}>}&\Psr\Log\AbstractLogger
     */
    private static function recordingLogger(): AbstractLogger
    {
        return new class extends AbstractLogger {
            /** @var list<string> */
            public array $channels = [];

            /** @var list<array{message: string, context: array<mixed>}> */
            public array $warnings = [];

            /**
             * @param  string  $name
             * @return self
             */
            public function channel(string $name): self
            {
                $this->channels[] = $name;

                return $this;
            }

            /**
             * @param  string|\Stringable  $message
             * @param  array<mixed>  $context
             * @return void
             */
            #[\Override]
            public function warning(string|\Stringable $message, array $context = []): void
            {
                $this->warnings[] = ['message' => (string) $message, 'context' => $context];
            }

            /**
             * @param  mixed  $level
             * @param  string|\Stringable  $message
             * @param  array<mixed>  $context
             * @return void
             */
            #[\Override]
            public function log(mixed $level, string|\Stringable $message, array $context = []): void {}
        };
    }
}
