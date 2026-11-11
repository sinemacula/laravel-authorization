<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Where `permissionsFor()` lists a subject's actions (AUTHZ-10.4, N71): the
 * active tenant, or none for the platform, the application, or none, and the
 * resource the actions are taken on, or none.
 *
 * A scope is named explicitly: `current()` captures the request's tenant and
 * application as the resolvers report them, `platform()` names no tenant and
 * `tenant()` names one. A null tenant always means the platform, never "the
 * request's tenant", and a null application means no application, as it does
 * for the subject resolver: only the grants for every application count. The
 * resource, set with `withResource()`, takes any form `check()` takes, and
 * names the target the actions are listed for: its own tenant goes through the
 * normal admission (see `ResourceScope`) and never replaces the active tenant.
 *
 * The scope is applied through `TenantScope::within()`, so the checks see its
 * tenant and application both as the ambient grant scope and as the subject's,
 * and the request's are back in place once they are decided, even when one
 * throws. What the resolution cache holds for the request's scope is kept
 * meanwhile and is back with it, unless a write dropped it, and a scope that is
 * already in place, such as `current()`, is not applied again, so listing in it
 * costs what checking in it costs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthorizationScope
{
    /**
     * Create a new authorization scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @param  mixed  $resource
     */
    private function __construct(

        /** The active tenant, or null for the platform, with no tenant active. */
        public ?Reference $tenant,

        /** The application, or null for none, when only grants for every application count. */
        public ?string $application,

        /** The resource the actions are taken on, in any form `check()` accepts, or null for none. */
        public mixed $resource = null,
    ) {}

    /**
     * Return the scope of the current request or job: its tenant and
     * application, as the resolvers report them, with no resource.
     *
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public static function current(): self
    {
        $tenant = TenantScope::currentTenant();

        return new self($tenant === null ? null : new Reference(...$tenant), TenantScope::currentApplication());
    }

    /**
     * Return the platform's scope, with no tenant active, on the application,
     * or on none, with no resource.
     *
     * @param  string|null  $application
     * @return self
     */
    public static function platform(?string $application = null): self
    {
        return new self(null, $application);
    }

    /**
     * Return the scope of the tenant, on the application, or on none, with no
     * resource. A tenant without a key is refused.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  string|null  $application
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public static function tenant(AuthorizableTenant|Model|Reference $tenant, ?string $application = null): self
    {
        $pair = TenantScope::extractTenantPair($tenant);

        return new self($tenant instanceof Reference ? $tenant : new Reference(...$pair), $application);
    }

    /**
     * Return this scope with the resource the actions are taken on, in any form
     * `check()` accepts, or with none for null.
     *
     * @param  mixed  $resource
     * @return self
     */
    public function withResource(mixed $resource): self
    {
        return new self($this->tenant, $this->application, $resource);
    }

    /**
     * Run the callback with this scope's tenant and application in place of the
     * request's, which are restored afterwards, even when it throws, with what
     * the resolution cache held for them. A scope already in place runs the
     * callback as it is.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $callback
     * @return TResult
     */
    public function within(\Closure $callback): mixed
    {
        if ($this->isInPlace()) {
            return $callback();
        }

        $enter = fn (): mixed => TenantScope::within($this->tenant, $this->application, $callback);
        $cache = ResolutionCache::instance();

        return $cache === null ? $enter() : $cache->batch($enter, true);
    }

    /**
     * Return the subject in this scope: its identity, guard, session and
     * credential's scopes kept, with this scope's tenant and application, or
     * null for a guest. A subject on the platform keeps its marker in the
     * platform's scope, and loses it in a tenant's, where this scope places it,
     * as it places a subject naming another tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @return ($subject is null ? null : \SineMacula\Laravel\Authorization\Subject)
     */
    public function subjectIn(?Subject $subject): ?Subject
    {
        if ($subject === null) {
            return null;
        }

        $platform = $subject->platform && $this->tenant === null;

        return new Subject($subject->subject, $subject->identity, $this->tenant, $this->application, $subject->guard, $subject->session, $subject->scopes, $platform);
    }

    /**
     * Determine whether this scope's tenant and application are those in place
     * already, with checks decided in the tenant rather than just below it, so
     * applying it would change nothing. A tenant in place that cannot be read
     * is never this scope's.
     *
     * @return bool
     */
    private function isInPlace(): bool
    {
        try {
            $tenant = TenantScope::currentTenant();
        } catch (InvalidTenantException) {
            return false;
        }

        $own = $this->tenant === null ? null : [$this->tenant->type, $this->tenant->id];

        return $tenant === $own && TenantScope::currentApplication() === $this->application && !TenantScope::isBelowTenant();
    }
}
