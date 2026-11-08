<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;

/**
 * Sets up the two parties of a preview for tests of `previewFor()`: a caller
 * signed in, in a session, a tenant and an application, holding the right to
 * preview or not, and the targets it previews.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait PreviewsSubjects
{
    /**
     * Make the caller the request's subject, its own identity, in the session,
     * tenant and application given, with the checker bound when one is given,
     * and return the manager built afresh for the request.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $caller
     * @param  string|null  $session
     * @param  object|null  $tenant
     * @param  string|null  $application
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker|null  $checker
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    protected function signIn(
        StubIdentity $caller,
        ?string $session = 'session-1',
        ?object $tenant = null,
        ?string $application = null,
        ?AuthenticationRequirementChecker $checker = null,
    ): AuthorizationManager {
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($caller, $caller, $tenant, $application, 'web', $session)));

        if ($checker !== null) {
            $this->app?->instance(AuthenticationRequirementChecker::class, $checker);
        }

        foreach (['authorization', AuthorizationManager::class, CheckContextFactory::class, ResolvedTenant::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager */
        return $this->app?->make(AuthorizationManager::class);
    }

    /**
     * Return a new identity with the id, granted the right to preview,
     * platform-wide, unless told not to.
     *
     * @param  string  $id
     * @param  bool  $isAllowed
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    protected static function previewer(string $id = 'previewer', bool $isAllowed = true): StubIdentity
    {
        $previewer = StubIdentity::query()->create(['id' => $id]);

        if ($isAllowed) {
            $previewer->givePermission(self::permission(PackagePermissions::SUBJECT_PREVIEW));
        }

        return $previewer;
    }

    /**
     * Return a new identity with the id, granted each of the permissions given,
     * platform-wide.
     *
     * @param  string  $id
     * @param  list<string>  $permissions
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    protected static function target(string $id = 'target', array $permissions = ['posts:read']): StubIdentity
    {
        $target = StubIdentity::query()->create(['id' => $id]);

        foreach ($permissions as $permission) {
            $target->givePermission(self::permission($permission));
        }

        return $target;
    }

    /**
     * Return the permission with the name, created on first use.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    protected static function permission(string $name): Permission
    {
        /** @var \SineMacula\Laravel\Authorization\Models\Permission */
        return Permission::query()->firstOrCreate(['name' => $name]);
    }

    /**
     * Attach a stored policy of the statements given, named as given, to the
     * grantee, platform-wide.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $grantee
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return void
     *
     * @throws \Throwable
     */
    protected static function attachStatements(StubIdentity $grantee, string $name, array $statements): void
    {
        $policy = Policy::query()->create(['name' => $name, 'document' => ['statements' => $statements]]);

        GrantService::instance()?->attachPolicy($grantee, $policy);
    }
}
