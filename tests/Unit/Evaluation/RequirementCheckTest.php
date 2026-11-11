<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\RequirementCheck;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\TestCase;

/**
 * Unit tests for the judging of a check's authentication requirements: met,
 * unmet and undecidable, the subject's session, and what the decision may be
 * reused for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RequirementCheck::class)]
final class RequirementCheckTest extends TestCase
{
    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-11-06 12:00:00');
    }

    /**
     * Release the clock.
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
     * A met requirement holds, and the checker is asked about the requirement
     * and the subject.
     *
     * @return void
     */
    public function testAMetRequirementHolds(): void
    {
        $checker     = new StubRequirementChecker(RequirementResult::met());
        $subject     = self::subject('session-1');
        $requirement = self::requirement();
        $result      = (new RequirementCheck($checker, $subject))->assess($requirement);

        self::assertSame(MatchOutcome::MATCHES, $result->outcome);
        self::assertNull($result->unmetRequirement);
        self::assertSame([[$requirement, $subject]], $checker->calls);
    }

    /**
     * An unmet requirement does not hold, and carries the requirement with the
     * parts the checker found unmet, in the requirement's order.
     *
     * @return void
     */
    public function testAnUnmetRequirementCarriesItsUnmetParts(): void
    {
        $requirement = self::requirement();
        $checker     = new StubRequirementChecker(RequirementResult::unmet(['phishing_resistant', 'multifactor']));
        $result      = (new RequirementCheck($checker, self::subject('session-1')))->assess($requirement);

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $result->outcome);
        self::assertSame('the authentication requirement is not met', $result->detail);
        self::assertEquals(new UnmetRequirement($requirement, ['multifactor', 'phishing_resistant']), $result->unmetRequirement);
    }

    /**
     * Unmet parts the requirement does not name are dropped, an unmet result
     * naming none of its parts leaves every part unmet, and the parts kept are
     * a list even when only a later part is unmet.
     *
     * @return void
     */
    public function testUnmetPartsAreThoseTheRequirementNames(): void
    {
        $requirement = self::requirement();

        $some = (new RequirementCheck(new StubRequirementChecker(RequirementResult::unmet(['assurance_level', 'multifactor'])), self::subject('s')))->assess($requirement);
        $none = (new RequirementCheck(new StubRequirementChecker(RequirementResult::unmet(['assurance_level'])), self::subject('s')))->assess($requirement);

        $later = (new RequirementCheck(new StubRequirementChecker(RequirementResult::unmet(['phishing_resistant'])), self::subject('s')))->assess($requirement);

        self::assertSame(['multifactor'], $some->unmetRequirement?->unmet);
        self::assertSame(['multifactor', 'phishing_resistant'], $none->unmetRequirement?->unmet);
        self::assertSame(['phishing_resistant'], $later->unmetRequirement?->unmet);
    }

    /**
     * A subject without a session meets no requirement, and the checker is
     * never asked.
     *
     * @return void
     */
    public function testANullSessionIsUnmetWithoutAskingTheChecker(): void
    {
        $checker = new StubRequirementChecker(RequirementResult::met());
        $result  = (new RequirementCheck($checker, self::subject(null)))->assess(self::requirement());

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $result->outcome);
        self::assertSame(['multifactor', 'phishing_resistant'], $result->unmetRequirement?->unmet);
        self::assertSame([], $checker->calls);
    }

    /**
     * Without a checker, or without a subject, every part is unmet, and a check
     * without a subject limits its decision to no session.
     *
     * @return void
     */
    public function testWithoutACheckerOrSubjectEveryPartIsUnmet(): void
    {
        $checker = new StubRequirementChecker(RequirementResult::met());
        $check   = new RequirementCheck($checker);

        self::assertSame(['multifactor', 'phishing_resistant'], (new RequirementCheck(null, self::subject('s')))->assess(self::requirement())->unmetRequirement?->unmet);
        self::assertSame(['multifactor', 'phishing_resistant'], $check->assess(self::requirement())->unmetRequirement?->unmet);
        self::assertSame([], $checker->calls);
        self::assertEquals(new RequirementFreshness(null), $check->freshness());
    }

    /**
     * A checker that throws makes the requirement undecidable, and the failure
     * is logged at debug level by class alone, never with its message.
     *
     * @return void
     */
    public function testACheckerThatThrowsIsUndecidable(): void
    {
        $logger  = $this->recordLogs();
        $checker = new StubRequirementChecker(new \RuntimeException('proof amr=pwd,otp'));
        $result  = (new RequirementCheck($checker, self::subject('session-1')))->assess(self::requirement());

        self::assertSame(MatchOutcome::UNDECIDABLE, $result->outcome);
        self::assertSame('the authentication requirement cannot be checked', $result->detail);
        self::assertNull($result->unmetRequirement);
        self::assertSame(
            [['debug', 'Authentication requirement checker ' . StubRequirementChecker::class . ' threw RuntimeException: the requirement is undecidable.']],
            \array_map(static fn (array $record): array => [$record['level'], $record['message']], $logger->records),
        );
        self::assertStringNotContainsString('amr', \serialize($logger->records));
    }

    /**
     * A met result whose instant has come is unmet, every part with it.
     *
     * @return void
     */
    public function testALapsedMetResultIsUnmet(): void
    {
        $check  = new RequirementCheck(new StubRequirementChecker(RequirementResult::met(new \DateTimeImmutable('2026-11-06 12:00:00'))), self::subject('s'));
        $result = $check->assess(self::requirement());

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $result->outcome);
        self::assertSame(['multifactor', 'phishing_resistant'], $result->unmetRequirement?->unmet);
        self::assertEquals(new RequirementFreshness('s'), $check->freshness());
    }

    /**
     * A check that read no requirement puts no limit on its decision.
     *
     * @return void
     */
    public function testNoFreshnessWithoutARequirement(): void
    {
        self::assertNull((new RequirementCheck(new StubRequirementChecker(RequirementResult::met()), self::subject('s')))->freshness());
    }

    /**
     * A check that read requirements limits its decision to the subject's
     * session and the earliest instant a met one stays met until, ignoring met
     * ones with no instant and unmet ones.
     *
     * @return void
     */
    public function testFreshnessIsTheSessionAndTheEarliestInstant(): void
    {
        $early   = new \DateTimeImmutable('2026-11-06 12:05:00');
        $late    = new \DateTimeImmutable('2026-11-06 12:30:00');
        $checker = new StubRequirementChecker(RequirementResult::met(), [
            'multifactor'                    => RequirementResult::met($late),
            'phishing_resistant'             => RequirementResult::met($early),
            'additional_verification'        => RequirementResult::unmet(['additional_verification']),
            'multifactor,phishing_resistant' => RequirementResult::met(),
        ]);
        $check = new RequirementCheck($checker, self::subject('session-1'));

        $check->assess(new AuthenticationRequirement(['multifactor' => null]));
        $check->assess(new AuthenticationRequirement(['multifactor' => null, 'phishing_resistant' => null]));

        self::assertEquals(new RequirementFreshness('session-1', $late), $check->freshness());

        $check->assess(new AuthenticationRequirement(['phishing_resistant' => null]));
        $check->assess(new AuthenticationRequirement(['multifactor' => null]));
        $check->assess(new AuthenticationRequirement(['additional_verification' => null]));

        self::assertEquals(new RequirementFreshness('session-1', $early), $check->freshness());
    }

    /**
     * Of two met requirements that stay met until the same instant, the first
     * read is the one kept.
     *
     * @return void
     */
    public function testOfTwoEqualInstantsTheFirstIsKept(): void
    {
        $first   = new \DateTimeImmutable('2026-11-06 12:05:00 UTC');
        $second  = new \DateTimeImmutable('2026-11-06 13:05:00 +01:00');
        $checker = new StubRequirementChecker(RequirementResult::met(), [
            'multifactor'        => RequirementResult::met($first),
            'phishing_resistant' => RequirementResult::met($second),
        ]);
        $check = new RequirementCheck($checker, self::subject('session-1'));

        $check->assess(new AuthenticationRequirement(['multifactor' => null]));
        $check->assess(new AuthenticationRequirement(['phishing_resistant' => null]));

        $freshness = $check->freshness();

        self::assertNotNull($freshness);
        self::assertSame($first, $freshness->metUntil);
        self::assertSame('+00:00', $freshness->metUntil->format('P'));
    }

    /**
     * Every requirement is put to the checker afresh, even one judged before in
     * the same check, so no result is reused.
     *
     * @return void
     */
    public function testNothingIsRemembered(): void
    {
        $checker = new StubRequirementChecker(RequirementResult::unmet(['multifactor']));
        $check   = new RequirementCheck($checker, self::subject('s'));

        $check->assess(self::requirement());
        $check->assess(self::requirement());

        self::assertCount(2, $checker->calls);
    }

    /**
     * A check about a subject without a session limits its decision to no
     * session.
     *
     * @return void
     */
    public function testFreshnessOutsideASession(): void
    {
        $check = new RequirementCheck(null, self::subject(null));

        $check->assess(self::requirement());

        self::assertEquals(new RequirementFreshness(null), $check->freshness());
    }

    /**
     * A check that read no requirement has read none.
     *
     * @return void
     */
    public function testNothingIsReadWithoutARequirement(): void
    {
        self::assertSame([], (new RequirementCheck(new StubRequirementChecker(RequirementResult::met()), self::subject('s')))->read());
    }

    /**
     * Every part of every requirement read is named, whether it was met, unmet
     * or undecidable, or judged without a checker or a session, once each and
     * sorted, whatever order the requirements and their parts were read in.
     *
     * @return void
     */
    public function testEveryPartReadIsNamedOnceSorted(): void
    {
        $checker = new StubRequirementChecker(RequirementResult::met(), ['phishing_resistant' => RequirementResult::unmet(['phishing_resistant'])]);
        $check   = new RequirementCheck($checker, self::subject('session-1'));

        $check->assess(new AuthenticationRequirement(['phishing_resistant' => null]));
        $check->assess(new AuthenticationRequirement(['multifactor' => null, 'assurance_level' => null], 'high'));
        $check->assess(new AuthenticationRequirement(['additional_verification' => null, 'multifactor' => 60]));

        self::assertSame(['additional_verification', 'assurance_level', 'multifactor', 'phishing_resistant'], $check->read());

        $unchecked = new RequirementCheck(null, self::subject(null));

        $unchecked->assess(self::requirement());
        $unchecked->assess(new AuthenticationRequirement(['multifactor' => null]));

        self::assertSame(['multifactor', 'phishing_resistant'], $unchecked->read());

        $undecidable = new RequirementCheck(new StubRequirementChecker(new \RuntimeException('checker down')), self::subject('session-1'));

        $undecidable->assess(new AuthenticationRequirement(['multifactor' => null, 'assurance_level' => null], 'high'));

        self::assertSame(['assurance_level', 'multifactor'], $undecidable->read());
    }

    /**
     * Return the requirement most tests judge: multifactor within fifteen
     * minutes, and a phishing-resistant authenticator.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement
     */
    private static function requirement(): AuthenticationRequirement
    {
        return new AuthenticationRequirement(['multifactor' => 900, 'phishing_resistant' => null]);
    }

    /**
     * Return a subject in the session given.
     *
     * @param  string|null  $session
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private static function subject(?string $session): Subject
    {
        $user = new \stdClass;

        return new Subject($user, $user, session: $session);
    }

    /**
     * Record what the package writes to its log channel.
     *
     * @return \Tests\Feature\Stubs\RecordingLogger
     */
    private function recordLogs(): RecordingLogger
    {
        $logger = new RecordingLogger;

        $this->app?->instance('log', $logger);

        return $logger;
    }
}
