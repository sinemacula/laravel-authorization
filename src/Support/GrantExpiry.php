<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;

/**
 * The seconds until the nearest of a set of grant expiries, so a resolution
 * built from the grants is cached no longer than they hold.
 *
 * Each expiry is read as the grant tables store it, in UTC: an instant, the
 * column's text, or null for a grant that never expires.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GrantExpiry
{
    /**
     * Return the seconds until the nearest of the expiries, starting from an
     * expiry already known, or null when none of them expires.
     *
     * @param  int|null  $nearest
     * @param  iterable<mixed>  $expiries
     * @return int|null
     */
    public static function nearest(?int $nearest, iterable $expiries): ?int
    {
        $now = Carbon::now()->getTimestamp();

        foreach ($expiries as $expiry) {
            $expiresAt = UtcDateTime::toUtc($expiry);

            if ($expiresAt === null) {
                continue;
            }

            $nearest = \min($nearest ?? \PHP_INT_MAX, $expiresAt->getTimestamp() - $now);
        }

        return $nearest;
    }
}
