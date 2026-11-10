<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Config\ReviewConfigValidator;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind;
use SineMacula\Laravel\Authorization\Reviews\Support\Definitions;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * One access review (AUTHZ-11.6, N93), an immutable value the review service
 * runs (see `AccessReview`): the question, the scope it reads, what it is
 * about, and the most rows it returns.
 *
 * - `holders()`: who holds a role, a permission or a policy, by any route, or
 *   by a direct grant alone. A permission means that definition, never a policy
 *   statement or a wildcard grant that might authorise its action;
 * - `holdings()`: what a subject holds, and where. Given a resolved subject,
 *   its principal's own grants and its identity's when they reach it (another
 *   model of the same kind, see `SubjectGrants::grantingIdentity()`), never a
 *   sibling principal's; given an identity, the identity's grants and those of
 *   every principal the identity directory lists, each row keeping its actual
 *   grantee, and the result saying whether that list was complete;
 * - `expiring()`: the stored grants, attachments and role edges whose expiry
 *   falls within the UTC half-open window `[from, until)`, each bound kept to
 *   the microsecond: an expiry is stored to the whole second, its fraction
 *   dropped, so a bound with a fraction is compared as the next whole second,
 *   which selects exactly the stored expiries within the window;
 * - `grantedBy()`: the stored grants whose `granted_by` pair is exactly the
 *   actor's, the last actor to grant or change each (N95);
 * - `unused()`: the live stored grants (roles and permissions granted, policies
 *   attached to grantees) with no observed use since the instant (N94): each
 *   row's `usage` says `unused` when grant usage tracking covered the whole
 *   window, from the later of the instant and the grant's creation to the
 *   review's instant, and `unknown` when it did not, or the grant's source
 *   cannot report its use. A grant observed in use within the window is left
 *   out. Usage is recorded only while tracking is on (see
 *   `Usage\UsageTracking`), so with it off every grant reads `unknown`.
 *
 * Every input is a plain value, a model or a resolved subject: nothing is read
 * from a request (D22). Every review is bounded: it returns at most its limit
 * of rows, `authorization.reviews.limit` (1000 by default, a whole number of at
 * least 1, validated at boot) unless `withLimit()` sets another, and says
 * whether more were left out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReviewQuery
{
    /** @var int The most rows a review returns when no limit is configured. */
    public const int DEFAULT_LIMIT = 1000;

    /**
     * Create a new review query.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind  $kind
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @param  int  $limit
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $target
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $identity
     * @param  bool  $isDirectOnly
     * @param  \Carbon\CarbonImmutable|null  $from
     * @param  \Carbon\CarbonImmutable|null  $until
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     */
    private function __construct(

        /** The question the review asks. */
        public ReviewKind $kind,

        /** The scope the review reads. */
        public ReviewScope $scope,

        /** The most rows the review returns. */
        public int $limit,

        /** The role, permission or policy whose holders are listed; null for any other review. */
        public ?Reference $target = null,

        /** The subject whose holdings are listed, in principal mode; null for any other review. */
        public ?Subject $subject = null,

        /** The identity whose holdings, and its principals', are listed, in identity mode; null for any other review. */
        public ?Reference $identity = null,

        /** Whether only the target's direct grants are listed, no route through a role. */
        public bool $isDirectOnly = false,

        /** The start of the expiry window, or the instant a review of unused grants looks back to, in UTC, inclusive. */
        public ?CarbonImmutable $from = null,

        /** The end of the expiry window, in UTC, exclusive. */
        public ?CarbonImmutable $until = null,

        /** The actor whose last grants are listed. */
        public ?Reference $actor = null,
    ) {}

    /**
     * Return the review of who holds the role, permission or policy in the
     * scope, by every route, or by direct grants alone.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $target
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @param  bool  $directOnly
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function holders(Model|Reference $target, ReviewScope $scope, bool $directOnly = false): self
    {
        $reference = Reference::of($target);

        if (Definitions::kindOf($reference->type) === null || $reference->id === '') {
            throw new \InvalidArgumentException('An access review lists the holders of a role, a permission or a policy, named by its model or a reference to it.');
        }

        return new self(ReviewKind::HOLDERS, $scope, self::defaultLimit(), target: $reference, isDirectOnly: $directOnly);
    }

    /**
     * Return the review of what the subject holds in the scope: a resolved
     * subject's principal and its identity's grants that reach it, or an
     * identity's grants and every principal's it owns, given a model or a
     * reference to it.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Subject|\SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function holdings(Model|Reference|Subject $subject, ReviewScope $scope): self
    {
        if (!$subject instanceof Subject) {
            return new self(ReviewKind::HOLDINGS, $scope, self::defaultLimit(), identity: self::named($subject));
        }

        $principal = $subject->subject;

        if (!$principal instanceof Model && !$principal instanceof Reference) {
            throw new \InvalidArgumentException('An access review lists the holdings of a subject whose principal is a model or a reference.');
        }

        self::named($principal);

        return new self(ReviewKind::HOLDINGS, $scope, self::defaultLimit(), subject: $subject);
    }

    /**
     * Return the review of the stored grants, attachments and role edges in the
     * scope whose expiry is at or after the start of the window and before its
     * end, each instant taken in UTC whatever zone it is given in.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @param  \DateTimeInterface  $from
     * @param  \DateTimeInterface  $until
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function expiring(ReviewScope $scope, \DateTimeInterface $from, \DateTimeInterface $until): self
    {
        $start = CarbonImmutable::instance($from)->utc();
        $end   = CarbonImmutable::instance($until)->utc();

        if (!$start->lessThan($end)) {
            throw new \InvalidArgumentException('An expiry window ends after it starts.');
        }

        return new self(ReviewKind::EXPIRING, $scope, self::defaultLimit(), from: $start, until: $end);
    }

    /**
     * Return the review of the stored grants in the scope the actor last
     * granted or changed: those whose `granted_by` pair is exactly the actor's.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $actor
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function grantedBy(Model|Reference $actor, ReviewScope $scope): self
    {
        return new self(ReviewKind::GRANTED_BY, $scope, self::defaultLimit(), actor: self::named($actor));
    }

    /**
     * Return the review of the live stored grants in the scope with no observed
     * use since the instant, taken in UTC whatever zone it is given in.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @param  \DateTimeInterface  $since
     * @return self
     */
    public static function unused(ReviewScope $scope, \DateTimeInterface $since): self
    {
        return new self(ReviewKind::UNUSED, $scope, self::defaultLimit(), from: CarbonImmutable::instance($since)->utc());
    }

    /**
     * Return the instant a review of unused grants looks back to, in UTC; null
     * for any other review, whose rows' use is read since each grant's
     * creation.
     *
     * @return \Carbon\CarbonImmutable|null
     */
    public function since(): ?CarbonImmutable
    {
        return $this->kind === ReviewKind::UNUSED ? $this->from : null;
    }

    /**
     * Return this review returning at most the number of rows given.
     *
     * @param  int  $limit
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withLimit(int $limit): self
    {
        if ($limit < 1) {
            throw new \InvalidArgumentException('An access review returns at most a whole number of rows of at least 1.');
        }

        return new self($this->kind, $this->scope, $limit, $this->target, $this->subject, $this->identity, $this->isDirectOnly, $this->from, $this->until, $this->actor);
    }

    /**
     * Return the kind of grant the target is, for a review of holders.
     *
     * @return \SineMacula\Laravel\Authorization\Enums\GrantTarget|null
     */
    public function targetKind(): ?GrantTarget
    {
        return $this->target === null ? null : Definitions::kindOf($this->target->type);
    }

    /**
     * Return the reference to whom the review is about: the principal of a
     * subject, or the identity, for a review of holdings; null otherwise.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function about(): ?Reference
    {
        $principal = $this->subject?->subject;

        return $principal instanceof Model || $principal instanceof Reference ? Reference::of($principal) : $this->identity;
    }

    /**
     * Return the most rows a review returns by default:
     * `authorization.reviews.limit`, or the default when it is not configured,
     * refusing one that is not a whole number of at least 1, as the config is
     * refused at boot, rather than falling back to another bound.
     *
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function defaultLimit(): int
    {
        return ReviewConfigValidator::limit(config('authorization.reviews.limit', self::DEFAULT_LIMIT));
    }

    /**
     * Return the reference to the record, refusing one without a key.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $record
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function named(Model|Reference $record): Reference
    {
        $reference = Reference::of($record);

        if ($reference->id === '') {
            throw new \InvalidArgumentException('An access review names a record by its morph type and a key.');
        }

        return $reference;
    }
}
