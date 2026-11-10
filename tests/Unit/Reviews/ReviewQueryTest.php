<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Unit tests for the typed, immutable access review query: the four questions,
 * their inputs refused when they name nothing, the UTC window and the limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ReviewQuery::class)]
final class ReviewQueryTest extends TestCase
{
    /**
     * A review of holders names a role, permission or policy, by model or
     * reference, and whether only direct grants count.
     *
     * @return void
     */
    public function testAReviewOfHoldersNamesItsTarget(): void
    {
        $scope = ReviewScope::everywhere();
        $role  = Role::query()->create(['name' => 'editor']);
        $query = ReviewQuery::holders($role, $scope);

        self::assertSame(
            [ReviewKind::HOLDERS, $scope, $role->getMorphClass(), Reference::of($role)->id, false],
            [$query->kind, $query->scope, $query->target?->type, $query->target?->id, $query->isDirectOnly],
        );
        self::assertSame(GrantTarget::ROLE, $query->targetKind());
        self::assertTrue(ReviewQuery::holders($role, $scope, true)->isDirectOnly);
        self::assertSame(GrantTarget::PERMISSION, ReviewQuery::holders(new Reference((new Permission)->getMorphClass(), 'p'), $scope)->targetKind());
        self::assertSame(GrantTarget::POLICY, ReviewQuery::holders(new Reference((new Policy)->getMorphClass(), 'p'), $scope)->targetKind());
        self::assertNull($query->about());
        self::assertNull(ReviewQuery::grantedBy(new Reference('user', '1'), $scope)->targetKind());
    }

    /**
     * A target that is no definition, or names no key, is refused.
     *
     * @return void
     */
    public function testATargetThatIsNoDefinitionIsRefused(): void
    {
        foreach ([new Reference('user', '1'), new Reference((new Role)->getMorphClass(), '')] as $target) {
            try {
                ReviewQuery::holders($target, ReviewScope::everywhere());
                self::fail('A target that is no definition was taken.');
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    /**
     * A review of holdings takes a resolved subject in principal mode, and a
     * model or reference to an identity in identity mode; either is what the
     * review is about.
     *
     * @return void
     */
    public function testAReviewOfHoldingsTakesASubjectOrAnIdentity(): void
    {
        $ann     = StubIdentity::query()->create(['id' => 'ann']);
        $subject = new Subject($ann, $ann);
        $scope   = ReviewScope::everywhere();

        $principal = ReviewQuery::holdings($subject, $scope);
        $identity  = ReviewQuery::holdings($ann, $scope);

        self::assertSame([ReviewKind::HOLDINGS, $subject, null], [$principal->kind, $principal->subject, $principal->identity]);
        self::assertSame('ann', $principal->about()?->id);
        self::assertSame([null, 'ann'], [$identity->subject, $identity->identity?->id]);
        self::assertSame('ann', $identity->about()?->id);
        self::assertSame('ref', ReviewQuery::holdings(new Subject(new Reference('user', 'ref'), null), $scope)->about()?->id);
    }

    /**
     * A subject or an identity that names no key is refused.
     *
     * @return void
     */
    public function testAnUnnamedSubjectIsRefused(): void
    {
        foreach ([new Subject(new StubIdentity, null), new StubIdentity, new Subject(new \stdClass, null)] as $subject) {
            try {
                ReviewQuery::holdings($subject, ReviewScope::everywhere());
                self::fail('An unnamed subject was taken.');
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    /**
     * A review of expiries takes its window in UTC, whatever zone it is given
     * in, and refuses a window that does not end after it starts.
     *
     * @return void
     */
    public function testAReviewOfExpiriesTakesAUtcWindow(): void
    {
        $from  = new Carbon('2030-01-01 09:00:00', 'America/New_York');
        $until = $from->copy()->addSecond();
        $query = ReviewQuery::expiring(ReviewScope::everywhere(), $from, $until);

        self::assertSame(ReviewKind::EXPIRING, $query->kind);
        self::assertSame(['2030-01-01 14:00:00', 'UTC'], [$query->from?->format('Y-m-d H:i:s'), $query->from?->getTimezone()->getName()]);
        self::assertSame('2030-01-01 14:00:01', $query->until?->format('Y-m-d H:i:s'));

        foreach ([$from, $from->copy()->subSecond()] as $end) {
            try {
                ReviewQuery::expiring(ReviewScope::everywhere(), $from, $end);
                self::fail('A window that does not end after it starts was taken.');
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    /**
     * A review of an actor's grants names the actor.
     *
     * @return void
     */
    public function testAReviewOfAnActorNamesTheActor(): void
    {
        $query = ReviewQuery::grantedBy(StubIdentity::query()->create(['id' => 'actor']), ReviewScope::everywhere());

        self::assertSame([ReviewKind::GRANTED_BY, 'actor'], [$query->kind, $query->actor?->id]);

        $this->expectException(\InvalidArgumentException::class);

        ReviewQuery::grantedBy(new Reference('user', ''), ReviewScope::everywhere());
    }

    /**
     * A review of unused grants looks back to its instant in UTC, kept when it
     * is bounded; every other review looks back to no instant.
     *
     * @return void
     */
    public function testAReviewOfUnusedGrantsLooksBackToItsInstant(): void
    {
        $query = ReviewQuery::unused(ReviewScope::everywhere(), new Carbon('2030-01-01 15:00:00', 'Europe/Paris'))->withLimit(3);

        self::assertSame(ReviewKind::UNUSED, $query->kind);
        self::assertSame(['2030-01-01 14:00:00', 'UTC', 3], [$query->since()?->format('Y-m-d H:i:s'), $query->since()?->getTimezone()->getName(), $query->limit]);
        self::assertNull(ReviewQuery::expiring(ReviewScope::everywhere(), new Carbon('2030-01-01'), new Carbon('2030-01-02'))->since());
    }

    /**
     * Every review is bounded: by the configured limit, by the default when
     * none is configured, or by the limit given, of at least one row, the rest
     * of the query kept; a configured limit that is not a whole number of at
     * least one refuses the review rather than fall back to another bound.
     *
     * @return void
     */
    public function testEveryReviewIsBounded(): void
    {
        $actor = new Reference('user', '1');

        self::assertSame(1000, ReviewQuery::DEFAULT_LIMIT);
        self::assertSame(1000, ReviewQuery::grantedBy($actor, ReviewScope::everywhere())->limit);

        config(['authorization.reviews.limit' => 25]);

        self::assertSame(25, ReviewQuery::defaultLimit());

        config(['authorization.reviews.limit' => 0]);

        // A review built while the limit is invalid is refused, never bounded
        // by another limit.
        self::assertSame('authorization.reviews.limit', self::refusedLimitKey(static fn (): ReviewQuery => ReviewQuery::grantedBy($actor, ReviewScope::everywhere())));

        foreach ([0, -1, '50', 1.5, null] as $invalid) {
            config(['authorization.reviews.limit' => $invalid]);

            try {
                ReviewQuery::defaultLimit();

                self::fail('An invalid configured limit was taken.');
            } catch (InvalidAuthorizationConfigException $exception) {
                self::assertSame('authorization.reviews.limit', $exception->getConfigKey());
            }
        }

        config(['authorization.reviews.limit' => 1]);

        self::assertSame(1, ReviewQuery::defaultLimit());

        $limited = ReviewQuery::grantedBy($actor, ReviewScope::everywhere())->withLimit(7);

        self::assertSame([7, ReviewKind::GRANTED_BY, '1'], [$limited->limit, $limited->kind, $limited->actor?->id]);
        self::assertSame(1, $limited->withLimit(1)->limit);

        $window = ReviewQuery::expiring(ReviewScope::everywhere(), new Carbon('2030-01-01 00:00:00', 'UTC'), new Carbon('2031-01-01 00:00:00', 'UTC'))->withLimit(3);

        self::assertSame('2030', $window->from?->format('Y'));
        self::assertSame('2031', $window->until?->format('Y'));

        $role    = new Reference((new Role)->getMorphClass(), 'r');
        $holders = ReviewQuery::holders($role, ReviewScope::everywhere(), true)->withLimit(3);

        self::assertSame(['r', true], [$holders->target?->id, $holders->isDirectOnly]);

        $subject = new Subject(new Reference('user', 'u'), null);

        self::assertSame($subject, ReviewQuery::holdings($subject, ReviewScope::everywhere())->withLimit(3)->subject);
        self::assertSame('i', ReviewQuery::holdings(new Reference('user', 'i'), ReviewScope::everywhere())->withLimit(3)->identity?->id);

        $this->expectException(\InvalidArgumentException::class);

        $limited->withLimit(0);
    }

    /**
     * Return the config key the callback is refused under for an invalid
     * configured limit, or null when it is not refused.
     *
     * @param  \Closure(): mixed  $callback
     * @return string|null
     */
    private static function refusedLimitKey(\Closure $callback): ?string
    {
        try {
            $callback();
        } catch (\Throwable $exception) {
            return $exception instanceof InvalidAuthorizationConfigException ? $exception->getConfigKey() : null;
        }

        return null;
    }
}
