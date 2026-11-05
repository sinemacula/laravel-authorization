<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use Psr\Log\AbstractLogger;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Models\Policy;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the policy hydration in `HasPolicies::getPolicies()`.
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

        self::assertSame(['authorization'], $logger->channels);
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
