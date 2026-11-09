<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when an access review is given a cursor it did not issue for that
 * review: one whose payload or signature was changed, one issued for another
 * query, another reviewer or the trusted path, one of another row schema
 * version, or anything that is not a cursor at all (see `Reviews\AccessReview`
 * and `Reviews\Support\ReviewCursor`).
 *
 * Its message is the same whatever was wrong, so a refusal says nothing of the
 * review, its rows or why the cursor was refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidReviewCursorException extends \InvalidArgumentException
{
    /**
     * Refuse the cursor.
     *
     * @return self
     */
    public static function refused(): self
    {
        return new self('The access review cursor is not valid for this review.');
    }
}
