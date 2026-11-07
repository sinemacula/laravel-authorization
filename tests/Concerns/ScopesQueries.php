<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\FixedSubjectResolver;

/**
 * Resolves the request a query is scoped in, and stores and attaches the
 * policies a query scoping test needs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ScopesQueries
{
    /**
     * Resolve the user as the request's subject, in the tenant and for the
     * application given, and return the manager built afresh for it.
     *
     * @param  object  $user
     * @param  object|null  $tenant
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    protected function resolveRequest(object $user, ?object $tenant = null, ?string $application = null): AuthorizationManager
    {
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($user, $user, $tenant, $application)));

        foreach (['authorization', AuthorizationManager::class, ResolvedTenant::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager */
        return $this->app?->make(AuthorizationManager::class);
    }

    /**
     * Return a stored policy of the statements.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    protected static function storedPolicy(string $name, array $statements): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => $statements]]);
    }

    /**
     * Attach a stored policy of the statements to the resource, a record or a
     * type.
     *
     * @param  mixed  $resource
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    protected static function attachToResource(mixed $resource, array $statements): Policy
    {
        $policy  = self::storedPolicy('attached-' . Str::random(6), $statements);
        $service = ResourcePolicyService::instance();

        self::assertInstanceOf(ResourcePolicyService::class, $service);

        $service->attach($policy, $resource);

        return $policy;
    }

    /**
     * Store a policy whose document cannot be read, and return its key.
     *
     * @return string
     */
    protected static function unreadablePolicy(): string
    {
        $id = (string) Str::uuid();

        DB::table('policies')->insert([
            'id'         => $id,
            'name'       => 'unreadable',
            'document'   => \json_encode(['statements' => [['effect' => 'allow', 'actions' => ['*'], 'unexpected' => true]]]),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $id;
    }

    /**
     * Return the refusal the callback throws, failing when it throws none.
     *
     * @param  \Closure(): mixed  $callback
     * @return \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    protected static function refusalOf(\Closure $callback): QueryScopeRefusedException
    {
        try {
            $callback();
        } catch (QueryScopeRefusedException $exception) {
            return $exception;
        }

        self::fail('The query scope was not refused.');
    }
}
