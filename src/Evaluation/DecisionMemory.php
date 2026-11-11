<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;

/**
 * Everything the current request or job remembers towards its decisions, and
 * the one call that has it forgotten (N112), so the rest of the request or job
 * decides afresh once a proof is recorded or revoked, a session signs in or
 * out, or the tenant is switched inside it.
 *
 * Forgetting clears the last decision, with its provenance and the session it
 * was recorded in (see `LastDecisionStore`); empties the resolution cache's
 * memo, in every scope, set aside or not, without touching the persistent store
 * or bumping a version key, since a proof changed is no grant changed (see
 * `ResolutionCache::tenantChanged()`); and drops the tenant and application
 * resolved for the request, so the next check asks the subject resolver again
 * for the subject, its session and its tenant, while a scope put in place with
 * `TenantScope::within()` or an `AuthorizationScope`, one already in place
 * included (see `TenantScope::pinned()`), stays as its caller set it until it
 * ends. It also moves the generation on, which what is held for longer than one
 * decision compares with the one it was read under: a batch of checks reads
 * ahead again from its next chunk, the request's subject included when it is
 * about it (see `CheckBatch`), a use of a preview admits its previewer again
 * (see `PreviewAdmission`), and a decision works out again whether a right is
 * limited (see `FurtherChecks`).
 *
 * The session caps are not held: the session policy source is asked once per
 * check, so the next check reads the credential's scopes afresh. A decision
 * already returned and an event already dispatched are observations of what was
 * decided then, and stand.
 *
 * It is bound with `scoped()`, so it belongs to the current request or job,
 * like the last decision, and its generation starts afresh in the next one.
 * Forgetting builds nothing the package refuses to build, so it never refuses:
 * while the package refuses (see `PackageState`), the resolution cache is left
 * as it is, as no check is decided to read it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DecisionMemory
{
    /** @var int How many times the request or job has forgotten its decisions, which what reads ahead compares with the value it read under. */
    private int $generation = 0;

    /**
     * Return the decision memory of the current request or job, binding it,
     * scoped, when the container does not yet hold it.
     *
     * @return self
     */
    public static function current(): self
    {
        $container = Container::getInstance();

        if (!$container->bound(self::class)) {
            $container->scoped(self::class);
        }

        /** @var self */
        return $container->make(self::class);
    }

    /**
     * Return the current generation, which moves on every time the decisions
     * are forgotten.
     *
     * @return int
     */
    public function generation(): int
    {
        return $this->generation;
    }

    /**
     * Forget everything the request or job remembers towards its decisions, the
     * last decision the store holds included.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore  $store
     * @return void
     */
    public function forget(LastDecisionStore $store): void
    {
        $this->generation++;

        $store->forget();

        $container = Container::getInstance();

        // A scope `within()` put in place is read first from a key of its own,
        // so it stays until it ends.
        $container->forgetInstance(ResolvedTenant::class);

        if (PackageState::of($container)?->isRefusing() === true) {
            return;
        }

        ResolutionCache::instance()?->tenantChanged(true);
    }
}
