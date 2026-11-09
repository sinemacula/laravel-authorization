<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind;
use SineMacula\Laravel\Authorization\Reviews\Support\HolderRoutes;
use SineMacula\Laravel\Authorization\Reviews\Support\HoldingRoutes;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun;
use SineMacula\Laravel\Authorization\Reviews\Support\RowCollector;
use SineMacula\Laravel\Authorization\Reviews\Support\StoredRows;
use SineMacula\Laravel\Authorization\Reviews\Support\SubjectStates;

/**
 * Runs access reviews (AUTHZ-11.6, N93 to N98): who holds a role, permission or
 * policy, what a subject holds, what expires, and what an actor last granted,
 * for periodic reviews and their sign-off.
 *
 * A review lists grant routes, never effective access: one row for each route
 * by which a subject holds a target through the stored grants, every row it
 * rests on live at the review's instant. It reads structure alone, the same
 * tenant chain, application matching, live-grant and definition-visibility
 * rules a check reads, and never evaluates a statement, condition, deny or cap
 * (D22), so a policy that only denies is held, and a holder may be denied what
 * it holds; `check()`, `permissionsFor()` and a preview say what a subject may
 * do. Boundaries, guardrails and resource-policy attachments restrict or extend
 * what is decided, but are not held, so no review lists them.
 *
 * `review()` runs a review as the reviewer, admitted first (see
 * `ReviewAdmission`): a refused review throws `AuthorizationException` before
 * anything is read, so it discloses no row, count, truncation or completeness.
 * `trusted()` runs one as trusted system work (N75), for a scheduled job or a
 * command, with no reviewer and no admission; nothing else falls back to it,
 * and an acting context that cannot be resolved is refused before a review is
 * reached.
 *
 * Every read is on the write connection, as every other grant read is, in a
 * fixed number of queries whatever the number of holders, and at most the
 * review's limit of rows, and one more, is held at a time (one subject's
 * holdings are read whole, then ordered). The rows come in one deterministic
 * order, the same on every supported database (see `Support\ReviewOrder`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AccessReview
{
    /**
     * Create a new access review service.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the identity directory is read from on every review of an identity's holdings. */
        private Container $container,
    ) {}

    /**
     * Run the review as the reviewer, once the reviewer is admitted to it.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $reviewer
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewResult
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function review(ReviewQuery $query, ActingContext $reviewer): ReviewResult
    {
        ReviewAdmission::admit($reviewer, ReviewResource::of($query));

        return $this->run($query);
    }

    /**
     * Run the review as trusted system work, with no reviewer and no admission.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewResult
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function trusted(ReviewQuery $query): ReviewResult
    {
        return $this->run($query);
    }

    /**
     * Run the review: read its rows, at most its limit and one more, and return
     * them with what is known of their subjects.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewResult
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private function run(ReviewQuery $query): ReviewResult
    {
        $run  = ReviewRun::of($query->scope);
        $rows = new RowCollector($run, $query->limit);

        $isComplete = match ($query->kind) {
            ReviewKind::HOLDERS  => HolderRoutes::read($run, $query, $rows),
            ReviewKind::HOLDINGS => HoldingRoutes::read($run, $query, $rows, $this->directory()),
            ReviewKind::EXPIRING,
            ReviewKind::GRANTED_BY => StoredRows::read($run, $query, $rows),
        };

        $read = $rows->rows($query->kind === ReviewKind::HOLDINGS);

        return new ReviewResult(SubjectStates::apply($read, $query->subject), $rows->isTruncated(), $isComplete, $run->now);
    }

    /**
     * Return the bound identity directory.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory
     */
    private function directory(): IdentityDirectory
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory */
        return $this->container->make(IdentityDirectory::class);
    }
}
