<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use Illuminate\Support\Carbon;

/**
 * How long a decision that read an authentication requirement may be reused
 * (AUTHZ-12.3, N37): within the session it was made in, and until the earliest
 * instant a met requirement it read stops being met.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RequirementFreshness
{
    /**
     * Create a new requirement freshness.
     *
     * @param  string|null  $session
     * @param  \DateTimeImmutable|null  $metUntil
     */
    public function __construct(

        /** The session the decision was made in; null when it was made outside one. */
        public ?string $session,

        /** The earliest instant a met requirement it read stops being met; null when none gave one. */
        public ?\DateTimeImmutable $metUntil = null,
    ) {}

    /**
     * Determine whether the decision may still be reused in the session at the
     * instant (now when none is given): it is the session the decision was made
     * in, and no met requirement it read has stopped being met.
     *
     * @param  string|null  $session
     * @param  \DateTimeInterface|null  $at
     * @return bool
     */
    public function holdsFor(?string $session, ?\DateTimeInterface $at = null): bool
    {
        return $session === $this->session && !$this->hasLapsed($at);
    }

    /**
     * Determine whether a met requirement the decision read has stopped being
     * met by the instant (now when none is given).
     *
     * @param  \DateTimeInterface|null  $at
     * @return bool
     */
    public function hasLapsed(?\DateTimeInterface $at = null): bool
    {
        return $this->metUntil !== null && ($at ?? Carbon::now()) >= $this->metUntil;
    }
}
