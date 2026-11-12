<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Observers;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Models\BreakGlassActivation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Bumps the versions of a break-glass activation's grantee whenever the
 * activation is saved or deleted, as a grant to the grantee bumps them, so the
 * next check, in every worker, reads the activation as it now is.
 *
 * A save that moves the activation to another grantee bumps both. The versions
 * are bumped at once, a failure of the store thrown so the write rolls back,
 * and again once the caller's transaction commits, so an entry a concurrent
 * check stored before the commit never holds; a failure then is written to the
 * log channel.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BreakGlassActivationObserver
{
    /**
     * Bump the versions of the grantee the activation names, and of the one it
     * named before, once it is saved.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation  $activation
     * @return void
     */
    public function saved(BreakGlassActivation $activation): void
    {
        self::bump([
            self::grantee($activation->getAttribute('authorizable_type'), $activation->getAttribute('authorizable_id')),
            self::grantee($activation->getRawOriginal('authorizable_type'), $activation->getRawOriginal('authorizable_id')),
        ]);
    }

    /**
     * Bump the versions of the grantee the activation names once it is deleted.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation  $activation
     * @return void
     */
    public function deleted(BreakGlassActivation $activation): void
    {
        self::bump([self::grantee($activation->getAttribute('authorizable_type'), $activation->getAttribute('authorizable_id'))]);
    }

    /**
     * Empty the resolution memo and bump the versions of the grantees now, and
     * again once the caller's transaction commits.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Support\Reference|null>  $grantees
     * @return void
     */
    private static function bump(array $grantees): void
    {
        $cache = ResolutionCache::instance();

        if ($cache === null) {
            return;
        }

        $keys = $cache->versionKeys([], \array_filter($grantees));

        $cache->invalidate($keys);

        /** @var \Illuminate\Database\DatabaseTransactionsManager $transactions */
        $transactions = Container::getInstance()->make('db.transactions');

        $transactions->addCallback(static fn () => $cache->invalidateQuietly($keys));
    }

    /**
     * Return the grantee the type and key name, or null when either is unset,
     * as before an activation is first saved.
     *
     * @param  mixed  $type
     * @param  mixed  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    private static function grantee(mixed $type, mixed $id): ?Reference
    {
        return \is_string($type) && \is_scalar($id) ? new Reference($type, (string) $id) : null;
    }
}
