<?php

declare(strict_types = 1);

namespace Tests\Feature\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for a resource pattern or identifier too long for `fnmatch()`,
 * decided by `check()` with Laravel's error handler and with warnings silenced,
 * and by `whereAuthorized()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Statement::class)]
final class LongResourcePatternsTest extends TestCase
{
    /** @var string The action the policies decide. */
    private const string ACTION = 'posts:view';

    /**
     * A deny whose substituted resource id is too long applies over a held
     * permission.
     *
     * @return void
     */
    public function testADenyOnALongSubstitutedIdApplies(): void
    {
        $post    = ScopedPost::query()->create(['title' => 'first']);
        $manager = self::manager([['effect' => 'deny', 'actions' => [self::ACTION], 'resources' => [self::type() . ':${input.id}']]], true);
        $input   = ['id' => \str_repeat('k', \PHP_MAXPATHLEN)];

        self::assertSame(DecisionReason::EXPLICIT_DENY, $manager->check(self::ACTION, $post, $input)->reason);
        self::assertSame(DecisionReason::EXPLICIT_DENY, self::silenced(static fn (): Decision => $manager->check(self::ACTION, $post, $input))->reason);
        self::assertSame([], self::kept($manager, $input));
    }

    /**
     * An allow whose substituted resource id is too long matches no record,
     * while its other patterns still do.
     *
     * @return void
     */
    public function testAnAllowOnALongSubstitutedIdMatchesOnlyItsOtherPatterns(): void
    {
        $first   = ScopedPost::query()->create(['id' => 1, 'title' => 'first']);
        $second  = ScopedPost::query()->create(['id' => 2, 'title' => 'second']);
        $manager = self::manager([['effect' => 'allow', 'actions' => [self::ACTION], 'resources' => [self::type() . ':${input.id}', self::type() . ':1']]]);
        $input   = ['id' => \str_repeat('k', \PHP_MAXPATHLEN)];

        self::assertTrue($manager->check(self::ACTION, $first, $input)->isAllowed());
        self::assertFalse($manager->check(self::ACTION, $second, $input)->isAllowed());
        self::assertSame([1], self::kept($manager, $input));
    }

    /**
     * A resource identifier too long to match a pattern denies the check as an
     * invalid policy over a held permission.
     *
     * @return void
     */
    public function testALongIdentifierMatchedAgainstAPatternDenies(): void
    {
        $manager  = self::manager([['effect' => 'deny', 'actions' => [self::ACTION], 'resources' => ['other:*']]], true);
        $resource = 'posts:' . \str_repeat('k', \PHP_MAXPATHLEN);

        self::assertSame(DecisionReason::INVALID_POLICY, $manager->check(self::ACTION, $resource)->reason);
        self::assertSame(DecisionReason::INVALID_POLICY, self::silenced(static fn (): Decision => $manager->check(self::ACTION, $resource))->reason);
        self::assertTrue($manager->check(self::ACTION, 'posts:' . \str_repeat('k', \PHP_MAXPATHLEN - 7))->isAllowed());
    }

    /**
     * Return a manager for a subject, holding the action or not, under a policy
     * of the statements.
     *
     * @param  list<array<string, mixed>>  $statements
     * @param  bool  $isHeld
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private static function manager(array $statements, bool $isHeld = false): AuthorizationManager
    {
        $user = StubGrantee::create(['id' => 'reader']);

        if ($isHeld) {
            $user->givePermission(Permission::create(['name' => self::ACTION]));
        }

        return Authorization::for($user)->withPolicies([EvaluationPolicy::fromArray(['name' => 'long', 'statements' => $statements])]);
    }

    /**
     * Return the keys of the posts the manager's subject may view.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  array<string, string>  $input
     * @return array<mixed>
     */
    private static function kept(AuthorizationManager $manager, array $input): array
    {
        return ScopedPost::query()->whereAuthorized(self::ACTION, $input, $manager)->orderBy('id')->pluck('id')->all(); // @phpstan-ignore method.notFound
    }

    /**
     * Return the decision the callback makes with warnings silenced, as they
     * are outside Laravel's error handler.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authorization\Evaluation\Decision  $callback
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function silenced(\Closure $callback): Decision
    {
        \set_error_handler(static fn (): bool => true);

        try {
            return $callback();
        } finally {
            \restore_error_handler();
        }
    }

    /**
     * Return the morph type of the posts.
     *
     * @return string
     */
    private static function type(): string
    {
        return (new ScopedPost)->getMorphClass();
    }
}
