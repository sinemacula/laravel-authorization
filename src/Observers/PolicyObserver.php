<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Observers;

use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Events\Policy\Created as PolicyCreated;
use SineMacula\Laravel\Authorization\Events\Policy\Deleted as PolicyDeleted;
use SineMacula\Laravel\Authorization\Events\Policy\Updated as PolicyUpdated;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * Row-lifecycle observer for the `Policy` model.
 *
 * Translates Eloquent's native `updating` / `created` / `updated` /
 * `deleted` events into the package's typed CRUD events.
 * System-protection hooks (`deleting`, `updating` guard, `saved`
 * bypass reset) live in
 * `HasSystemProtection::bootHasSystemProtection()` and run
 * independently of this observer.
 *
 * Policies are not tenant-scoped — there is no `saving` hook or
 * tenant-columns invariant. Unlike `Role` and `Permission`, a policy
 * row applies globally.
 *
 * Registered via `#[ObservedBy(PolicyObserver::class)]` on the
 * `Policy` model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PolicyObserver
{
    /** @var \WeakMap<\SineMacula\Laravel\Authorization\Models\Policy, array<string, mixed>>|null Pre-update snapshots bridging `updating` and `updated`; static so it survives per-event observer resolution. */
    private static ?\WeakMap $snapshots = null;

    /**
     * Capture the pre-update attribute snapshot so the paired
     * `updated` hook can emit a complete before/after diff.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     */
    public function updating(Policy $policy): void
    {
        $snapshot = [];

        foreach (\array_keys($policy->getDirty()) as $key) {
            $snapshot[$key] = $policy->getOriginal($key);
        }

        self::snapshots()[$policy] = $snapshot;
    }

    /**
     * Emit the typed `PolicyCreated` event.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     */
    public function created(Policy $policy): void
    {
        Event::dispatch(new PolicyCreated($policy));
    }

    /**
     * Emit the typed `PolicyUpdated` event with the before/after
     * diff captured in the paired `updating` hook.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     */
    public function updated(Policy $policy): void
    {
        $snapshots = self::snapshots();
        $before    = $snapshots[$policy] ?? [];

        Event::dispatch(new PolicyUpdated($policy, [
            'before' => $before,
            'after'  => $policy->getChanges(),
        ]));

        unset($snapshots[$policy]);
    }

    /**
     * Emit the typed `PolicyDeleted` event.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     */
    public function deleted(Policy $policy): void
    {
        Event::dispatch(new PolicyDeleted($policy));
    }

    /**
     * Return the shared snapshot map, creating it on first access.
     *
     * @return \WeakMap<\SineMacula\Laravel\Authorization\Models\Policy, array<string, mixed>>
     */
    private static function snapshots(): \WeakMap
    {
        return self::$snapshots ??= new \WeakMap;
    }
}
