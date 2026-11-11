<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use Illuminate\Support\Carbon;

/**
 * How long a decision that read an authentication requirement may be reused
 * (AUTHZ-12.3, N37): within the session it was made in, and until the earliest
 * instant a met requirement it read stops being met.
 *
 * The session is kept only as a non-reversible fingerprint, its SHA-256 hash,
 * never the session id itself, so a decision carrying it is still safe to log,
 * store and put on an event. Every session it is compared with is fingerprinted
 * the same way first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RequirementFreshness
{
    /** @var string|null The fingerprint of the session the decision was made in, never its id; null when made outside one. */
    public ?string $session;

    /** @var \DateTimeImmutable|null The earliest instant a met requirement it read stops being met; null when none gave one. */
    public ?\DateTimeImmutable $metUntil;

    /**
     * Create a new requirement freshness for the session the decision was made
     * in, which is fingerprinted and never kept.
     *
     * @param  string|null  $session
     * @param  \DateTimeImmutable|null  $metUntil
     */
    public function __construct(?string $session, ?\DateTimeImmutable $metUntil = null)
    {
        $this->session  = self::fingerprintOf($session);
        $this->metUntil = $metUntil;
    }

    /**
     * Determine whether the decision may still be reused in the session at the
     * instant (now when none is given): it is the session the decision was made
     * in, compared by fingerprint, and no met requirement it read has stopped
     * being met.
     *
     * @param  string|null  $session
     * @param  \DateTimeInterface|null  $at
     * @return bool
     */
    public function holdsFor(?string $session, ?\DateTimeInterface $at = null): bool
    {
        return self::fingerprintOf($session) === $this->session && !$this->hasLapsed($at);
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

    /**
     * Return the stricter of two freshnesses of decisions made in the same
     * session, either of which may be absent: the one whose met requirement
     * stops being met first, the first when neither stops or both stop at the
     * same instant, or null when neither is given.
     *
     * @param  self|null  $first
     * @param  self|null  $second
     * @return self|null
     *
     * @internal
     */
    public static function stricterOf(?self $first, ?self $second): ?self
    {
        if ($first === null || $second === null) {
            return $first ?? $second;
        }

        return $second->metUntil !== null && ($first->metUntil === null || $second->metUntil < $first->metUntil) ? $second : $first;
    }

    /**
     * Return the non-reversible fingerprint of the session, its SHA-256 hash,
     * or null when there is no session.
     *
     * @param  string|null  $session
     * @return string|null
     */
    private static function fingerprintOf(?string $session): ?string
    {
        return $session === null ? null : \hash('sha256', $session);
    }
}
