<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\ReviewAdmission;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewResource;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\PreviewsSubjects;
use Tests\Concerns\ReviewsAccess;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\TestCase;

/**
 * Feature tests for the admission of an access review (N96): the right is
 * decided as the reviewer, through ordinary `check()`, on the review resource
 * in the reviewed scope; a review across a reach is refused when anything could
 * limit the right anywhere in it; a refusal discloses nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ReviewAdmission::class)]
final class ReviewAdmissionTest extends TestCase
{
    use CatchesRefusals, PreviewsSubjects, ReviewsAccess {
        ReviewsAccess::permission insteadof PreviewsSubjects;
        PreviewsSubjects::permission as previewPermission;
    }

    /**
     * A review of one tenant needs the right there: granted in the tenant it is
     * admitted, granted in another it is refused, whichever tenant the reviewer
     * is in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReviewOfATenantNeedsTheRightThere(): void
    {
        $this->tree();

        $reviewer = self::reviewer('reviewer', self::tenant('acct1'));

        $this->signIn($reviewer, 'session-1', self::tenant('acct2'));

        $query = ReviewQuery::holders(self::role('reviewed'), ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none()));

        self::assertSame([], self::reviews()->review($query, ActingContext::current())->rows);

        $other = ReviewQuery::holders(self::role('other'), ReviewScope::appliesIn(self::tenant('acct2'), ApplicationSelector::none()));

        self::assertRefusedAs(DecisionReason::NO_MATCH, static fn (): mixed => self::reviews()->review($other, ActingContext::current()));
    }

    /**
     * A review rooted within a tenant needs a right that reaches below it: a
     * grant at the tenant's node alone is refused, at the administration stage.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReviewOfASubtreeNeedsARightReachingBelow(): void
    {
        $this->tree();

        $subtree = self::reviewer('subtree', self::tenant('org1'));
        $node    = self::reviewer('node', self::tenant('org1'), false);
        $query   = ReviewQuery::holders(self::role('reviewed'), ReviewScope::rootedWithin(self::tenant('org1')));

        $this->signIn($subtree);

        self::assertSame([], self::reviews()->review($query, ActingContext::current())->rows);

        $this->signIn($node);

        $refusal = self::assertRefusedAs(DecisionReason::ADMINISTRATION_SCOPE, static fn (): mixed => self::reviews()->review($query, ActingContext::current()));

        self::assertSame(DecisionStage::ADMINISTRATION, $refusal->getDecision()?->stage);
    }

    /**
     * A deny in one child tenant refuses a review across a reach that holds it,
     * the platform's or the parent's subtree, while a review of a sibling is
     * admitted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChildTenantsDenyBlocksABroadReview(): void
    {
        $this->tree();

        $reviewer = self::reviewer('reviewer', null);
        $role     = self::role('no-reviews');

        self::grants()->attachPolicy($role, self::denying());
        self::grants()->grantRole($reviewer, $role, tenant: self::tenant('team1'));

        $this->signIn($reviewer);

        $reviewed = self::role('reviewed');
        $review   = static fn (ReviewScope $scope): mixed => self::reviews()->review(ReviewQuery::holders($reviewed, $scope), ActingContext::current());

        self::assertRefusedAs(DecisionReason::ADMINISTRATION_SCOPE, static fn (): mixed => $review(ReviewScope::everywhere()));
        self::assertRefusedAs(DecisionReason::ADMINISTRATION_SCOPE, static fn (): mixed => $review(ReviewScope::appliesIn(null, ApplicationSelector::any())));
        self::assertRefusedAs(DecisionReason::ADMINISTRATION_SCOPE, static fn (): mixed => $review(ReviewScope::rootedWithin(self::tenant('org1'))));
        self::assertRefusedAs(DecisionReason::EXPLICIT_DENY, static fn (): mixed => $review(ReviewScope::appliesIn(self::tenant('team1'), ApplicationSelector::none())));

        self::assertSame([], $review(ReviewScope::rootedWithin(self::tenant('acct2')))->rows);
        self::assertSame([], $review(ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none()))->rows);
    }

    /**
     * A session cap that does not cover the right refuses the review, and so
     * does a step-up the right needs and the session has not met, as an
     * authorization exception carrying the decision.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSessionCapsAndStepUpApply(): void
    {
        $reviewer = self::reviewer('reviewer', null);
        $query    = ReviewQuery::holders(self::role('reviewed'), ReviewScope::everywhere());

        $this->signIn($reviewer);

        self::assertRefusedAs(DecisionReason::SESSION_POLICY, static fn (): mixed => self::reviews()->review($query, ActingContext::current()->capped(['posts:*'])));
        self::assertSame([], self::reviews()->review($query, ActingContext::current()->capped(['authorization:review.*']))->rows);

        $stepped = StubIdentity::query()->create(['id' => 'stepped']);

        self::attachStatements($stepped, 'stepped-up-review', [self::requiring(PackagePermissions::REVIEW_READ)]);

        $this->signIn($stepped, 'session-1', null, null, new StubRequirementChecker(RequirementResult::unmet(['multifactor'])));

        $refusal = self::assertRefusedAs(DecisionReason::INSUFFICIENT_AUTHENTICATION, static fn (): mixed => self::reviews()->review($query, ActingContext::current()));

        self::assertSame(AuthorizationException::class, $refusal::class);
    }

    /**
     * A policy restricts who may review what by the review resource's
     * attributes: here, every review but one of an actor's grants. Across a
     * reach, such a deny could limit the right, so it refuses every review.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyRestrictsReviewsByTheirAttributes(): void
    {
        $reviewer = self::reviewer('reviewer', null);

        self::attachStatements(
            $reviewer,
            'no-actor-reviews',
            [['effect' => 'deny', 'actions' => [PackagePermissions::REVIEW_READ], 'conditions' => ['eq' => ['resource.query' => 'granted_by']]]],
        );

        $this->signIn($reviewer);

        $here = ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none());

        self::assertSame([], self::reviews()->review(ReviewQuery::holders(self::role('reviewed'), $here), ActingContext::current())->rows);
        self::assertRefusedAs(DecisionReason::EXPLICIT_DENY, static fn (): mixed => self::reviews()->review(ReviewQuery::grantedBy($reviewer, $here), ActingContext::current()));

        // Across a reach, a deny that could limit the right refuses,
        // conditional or not.
        self::assertRefusedAs(
            DecisionReason::ADMINISTRATION_SCOPE,
            static fn (): mixed => self::reviews()->review(ReviewQuery::holders(self::role('other'), ReviewScope::everywhere()), ActingContext::current()),
        );
    }

    /**
     * A refusal is recorded and reported as any refused check is, with the one
     * generic line, and discloses nothing of the review: no row, count,
     * truncation or completeness.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalIsReportedAndDisclosesNothing(): void
    {
        Event::fake([AuthorizationFailed::class]);

        $reviewer = StubIdentity::query()->create(['id' => 'nobody']);
        $holder   = self::identity('holder');
        $role     = self::role('reviewed');

        self::grants()->grantRole($holder, $role);

        $manager = $this->signIn($reviewer);
        $refusal = self::assertRefusedAs(
            DecisionReason::NO_MATCH,
            static fn (): mixed => self::reviews()->review(ReviewQuery::holders($role, ReviewScope::everywhere()), ActingContext::current()),
        );

        Event::assertDispatched(AuthorizationFailed::class, static fn (AuthorizationFailed $event): bool => $event->action === PackagePermissions::REVIEW_READ);

        self::assertSame($manager->lastDecision(), $refusal->getDecision());
        self::assertStringNotContainsString('holder', $refusal->getMessage());
        self::assertStringNotContainsString(Reference::of($role)->id, $refusal->getMessage());
        self::assertSame([], \array_values(\array_filter(\get_object_vars($refusal), static fn (mixed $value): bool => \is_array($value) && $value !== [])));
    }

    /**
     * An admitted review in a tenant shows the inherited origins that apply
     * there, a platform grant and a parent's grant reaching below, but never
     * enumerates the holders in other tenants those origins also reach, nor a
     * child's or a sibling's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testScopedDisclosureNeverReachesOtherTenants(): void
    {
        $this->tree();

        $role = self::role('reviewed');

        self::grants()->grantRole(self::identity('platform'), $role);
        self::grants()->grantRole(self::identity('parent'), $role, tenant: self::tenant('org1'));
        self::grants()->grantRole(self::identity('own'), $role, tenant: self::tenant('acct1'));
        self::grants()->grantRole(self::identity('child'), $role, tenant: self::tenant('team1'));
        self::grants()->grantRole(self::identity('sibling'), $role, tenant: self::tenant('acct2'));
        self::grants()->grantRole(self::identity('elsewhere'), $role, tenant: self::tenant('org2'));

        $this->signIn(self::reviewer('reviewer', self::tenant('acct1')));

        $rows = self::reviews()->review(ReviewQuery::holders($role, ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none())), ActingContext::current())->rows;

        self::assertEqualsCanonicalizing(['platform', 'parent', 'own'], \array_map(static fn ($row): string => $row->subject->id, $rows));
    }

    /**
     * An export right is weighed across the reach as the read right is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheExportRightIsWeighedAcrossTheReach(): void
    {
        $this->tree();

        $reviewer = StubIdentity::query()->create(['id' => 'exporter']);

        self::grants()->grantPermission($reviewer, self::permission(PackagePermissions::REVIEW_EXPORT), tenant: self::tenant('org1'), includeSubtree: false);

        $this->signIn($reviewer);

        $resource = ReviewResource::of(ReviewQuery::holders(self::role('reviewed'), ReviewScope::rootedWithin(self::tenant('org1'))));

        self::assertRefusedAs(DecisionReason::ADMINISTRATION_SCOPE, static function () use ($resource): void {
            ReviewAdmission::admit(ActingContext::current(), $resource, PackagePermissions::REVIEW_EXPORT);
        });
    }

    /**
     * Return a new identity with the id, granted the review right in the
     * tenant, or platform-wide for none, reaching below it unless told not to.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $isSubtree
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function reviewer(string $id, ?Reference $tenant, bool $isSubtree = true): StubIdentity
    {
        $reviewer = StubIdentity::query()->create(['id' => $id]);

        self::grants()->grantPermission($reviewer, self::right(), tenant: $tenant, includeSubtree: $isSubtree);

        return $reviewer;
    }

    /**
     * Return the review right, created on first use.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function right(): Permission
    {
        return self::previewPermission(PackagePermissions::REVIEW_READ);
    }

    /**
     * Return a stored policy denying the review right.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function denying(): Policy
    {
        /** @var \SineMacula\Laravel\Authorization\Models\Policy */
        return Policy::query()->create(['name' => 'no-reviews', 'document' => ['statements' => [['effect' => 'deny', 'actions' => [PackagePermissions::REVIEW_READ]]]]]);
    }

    /**
     * Assert the callback is refused with an authorization exception of the
     * reason, and return it.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @param  \Closure(): mixed  $callback
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function assertRefusedAs(DecisionReason $reason, \Closure $callback): AuthorizationException
    {
        $refusal = self::refusalOf($callback);

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame($reason, $refusal->getReason());

        return $refusal;
    }
}
