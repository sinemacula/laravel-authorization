<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Testing\Concerns\AuthorizationAssertions;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;

/**
 * Seeds the subjects, grants and policies the middleware and Blade tests check,
 * and runs a check expecting it to be denied.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ChecksAccess
{
    use AuthorizationAssertions;

    /**
     * Make the given model the subject of every check, or make no subject the
     * request's.
     *
     * @param  object|null  $subject
     * @return void
     */
    protected function actAs(?object $subject): void
    {
        if ($subject === null) {
            $this->app?->instance(SubjectResolver::class, new StubSubjectResolver);
            $this->app?->forgetInstance('authorization');
            $this->app?->forgetInstance(AuthorizationManager::class);

            Authorization::clearResolvedInstance('authorization');

            return;
        }

        $this->actingAsSubject(new Subject($subject, $subject));
    }

    /**
     * Create an identity holding the given roles and direct permissions,
     * creating each row in the `web` guard when it does not exist yet.
     *
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    protected static function identityHolding(array $roles = [], array $permissions = []): StubIdentity
    {
        $identity = StubIdentity::create(['id' => (string) Str::uuid()]);

        foreach ($roles as $role) {
            $identity->assignRole(Role::query()->firstOrCreate(['name' => $role, 'guard' => 'web']));
        }

        foreach ($permissions as $permission) {
            $identity->givePermission(Permission::query()->firstOrCreate(['name' => $permission, 'guard' => 'web']));
        }

        return $identity;
    }

    /**
     * Attach a policy with one statement to the identity.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  string  $effect
     * @param  list<string>  $actions
     * @param  list<string>  $resources
     * @return void
     */
    protected static function attachStatement(StubIdentity $identity, string $effect, array $actions, array $resources = ['*']): void
    {
        $identity->attachPolicy(Policy::create([
            'name'     => (string) Str::uuid(),
            'document' => [
                'statements' => [
                    ['effect' => $effect, 'actions' => $actions, 'resources' => $resources],
                ],
            ],
        ]));
    }

    /**
     * Make the policy resolver give every subject one policy allowing the
     * actions on every resource, whether or not it can hold policies itself.
     * Call it before choosing the subject, which rebuilds the manager.
     *
     * @param  list<string>  $actions
     * @return void
     */
    protected function allowEverySubject(array $actions): void
    {
        $policy = EvaluationPolicy::fromArray([
            'name'       => 'every-subject',
            'statements' => [['effect' => 'allow', 'actions' => $actions, 'resources' => ['*']]],
        ]);

        $this->app?->instance(PolicyResolver::class, new class ($policy) implements PolicyResolver {
            /**
             * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
             */
            public function __construct(

                /** The policy every subject is given. */
                private readonly EvaluationPolicy $policy,
            ) {}

            /**
             * @param  object  $principal
             * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
             */
            #[\Override]
            public function policiesFor(object $principal): array
            {
                return [$this->policy];
            }
        });
    }

    /**
     * Run the check and return the denial it throws.
     *
     * @param  \Closure(): mixed  $check
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    protected static function denialOf(\Closure $check): AuthorizationException
    {
        try {
            $check();
        } catch (AuthorizationException $exception) {
            return $exception;
        }

        self::fail('Expected the check to be denied.');
    }

    /**
     * Resolve the middleware from the container, as Laravel does, and run it
     * with the given arguments.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware>  $middleware
     * @param  \Illuminate\Http\Request  $request
     * @param  string  ...$arguments
     * @return \Illuminate\Http\Response
     */
    protected function runMiddleware(string $middleware, Request $request, string ...$arguments): Response
    {
        $instance = $this->app?->make($middleware);

        self::assertInstanceOf(AbstractAuthorizationMiddleware::class, $instance);

        $response = $instance->handle($request, self::passThrough(), ...$arguments);

        self::assertInstanceOf(Response::class, $response);

        return $response;
    }

    /**
     * Whether the middleware admits the request with the given arguments.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware>  $middleware
     * @param  \Illuminate\Http\Request  $request
     * @param  string  ...$arguments
     * @return bool
     */
    protected function admits(string $middleware, Request $request, string ...$arguments): bool
    {
        try {
            $this->runMiddleware($middleware, $request, ...$arguments);
        } catch (AuthorizationException) {
            return false;
        }

        return true;
    }

    /**
     * Declare the stub permission enum, as an application configuring it would,
     * and boot the provider again, so the Gate asks the package about every
     * case.
     *
     * @return void
     */
    protected function registerPermissionGates(): void
    {
        config(['authorization.permission_enums' => [PermissionEnum::class]]);

        if ($this->app === null) {
            return;
        }

        (new AuthorizationServiceProvider($this->app))->boot();
    }

    /**
     * Build an incoming request.
     *
     * @return \Illuminate\Http\Request
     */
    protected static function request(): Request
    {
        return Request::create('/test', 'GET');
    }

    /**
     * A pass-through `$next` closure that proves the middleware forwarded the
     * request.
     *
     * @return \Closure(\Illuminate\Http\Request): \Illuminate\Http\Response
     */
    protected static function passThrough(): \Closure
    {
        return static fn (): Response => new Response('ok', 200);
    }
}
