<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Event;
use Illuminate\Translation\Translator as TranslatorImplementation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware;
use SineMacula\Laravel\Authorization\Http\Middleware\AuthorizeAction;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Concerns\ChecksAccess;
use Tests\Concerns\RefusesThePackage;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\TestCase;

/**
 * Feature coverage for what every shipped route middleware shares: the subject
 * the subject resolver returns (with the shipped resolver, the user Laravel
 * signed in), the arguments it takes, and the denial it throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AbstractAuthorizationMiddleware::class)]
#[CoversClass(RequireRole::class)]
#[CoversClass(RequirePermission::class)]
#[CoversClass(AuthorizeAction::class)]
final class AbstractAuthorizationMiddlewareTest extends TestCase
{
    use ChecksAccess, RefusesThePackage;

    /**
     * With no user signed in there is no subject, and every middleware answers
     * unauthenticated.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware>  $middleware
     * @param  string  $names
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    #[TestWith([RequireRole::class, 'admin'])]
    #[TestWith([RequirePermission::class, 'posts:create'])]
    #[TestWith([AuthorizeAction::class, 'posts:create'])]
    public function testWithoutASignedInUserTheRequestIsUnauthenticated(string $middleware, string $names): void
    {
        $this->seedGrantedUser();

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Unauthenticated.');

        $this->runMiddleware($middleware, self::request(), $names);
    }

    /**
     * The user Laravel signed in passes the role and permission it holds, with
     * no resolver of the application's own, and the request is passed on.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testTheSignedInUserPassesWhatItHolds(): void
    {
        $this->actingAs($this->seedGrantedUser());

        self::assertSame('ok', $this->runMiddleware(RequireRole::class, self::request(), 'admin')->getContent());
        self::assertSame('ok', $this->runMiddleware(RequirePermission::class, self::request(), 'posts:create')->getContent());
        self::assertSame('ok', $this->runMiddleware(AuthorizeAction::class, self::request(), 'posts:create')->getContent());
    }

    /**
     * The user Laravel signed in is refused a role it does not hold and an
     * action it is not allowed, each with the generic denial message.
     *
     * @return void
     */
    public function testTheSignedInUserIsRefusedWhatItLacks(): void
    {
        $this->actingAs($this->seedGrantedUser());

        $role   = self::denialOf(fn (): Response => $this->runMiddleware(RequireRole::class, self::request(), 'auditor'));
        $action = self::denialOf(fn (): Response => $this->runMiddleware(RequirePermission::class, self::request(), 'posts:delete'));

        self::assertSame('This action is unauthorized.', $role->getMessage());
        self::assertSame(DecisionReason::NO_MATCH, $role->getReason());
        self::assertSame('This action is unauthorized.', $action->getMessage());
        self::assertSame(DecisionReason::NO_MATCH, $action->getReason());
    }

    /**
     * Two arguments are taken; a third is refused, even without a subject.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAThirdArgumentIsRefused(): void
    {
        $this->actingAs($this->seedGrantedUser());

        self::assertSame(200, $this->runMiddleware(RequireRole::class, self::request(), 'admin', 'web')->getStatusCode());

        $this->actAs(null);

        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage(RequireRole::class . ' takes at most two arguments, 3 given. Separate several names with \'|\', not \',\'.');

        $this->runMiddleware(RequireRole::class, self::request(), 'admin', 'editor', 'auditor');
    }

    /**
     * With no arguments nothing is named, which is a mistake in the route, and
     * every middleware refuses it, even without a subject.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware>  $middleware
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    #[TestWith([RequireRole::class])]
    #[TestWith([RequirePermission::class])]
    #[TestWith([AuthorizeAction::class])]
    public function testNoArgumentsAreRefused(string $middleware): void
    {
        $this->actAs(null);

        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage($middleware . ' names nothing to check. List one or more names, separated by \'|\'.');

        $this->runMiddleware($middleware, self::request());
    }

    /**
     * Any allowed action admits the request and the rest are not decided; when
     * none is, the last one is authorised, firing `AuthorizationFailed` once.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAnyAllowedActionAdmitsAndTheLastIsAuthorized(): void
    {
        $this->actingAs($this->seedGrantedUser());

        Event::fake([AuthorizationFailed::class]);

        self::assertTrue($this->admits(RequirePermission::class, self::request(), 'posts:create|posts:delete'));
        self::assertTrue($this->admits(RequirePermission::class, self::request(), 'posts:delete|posts:create'));
        Event::assertNotDispatched(AuthorizationFailed::class);

        self::assertFalse($this->admits(RequirePermission::class, self::request(), 'posts:update|posts:delete'));
        Event::assertDispatchedTimes(AuthorizationFailed::class, 1);
        Event::assertDispatched(AuthorizationFailed::class, static fn (AuthorizationFailed $event): bool => $event->action === 'posts:delete');
    }

    /**
     * A middleware the container resolves words every denial with the generic
     * line, in the translator's current locale.
     *
     * @return void
     */
    public function testDenialsAreTranslatedInTheCurrentLocale(): void
    {
        $this->inFrench();

        $this->actingAs($this->seedGrantedUser());

        self::assertSame('Action non autorisée.', self::denialOf(fn (): Response => $this->runMiddleware(RequireRole::class, self::request(), 'auditor'))->getMessage());
        self::assertSame('Action non autorisée.', self::denialOf(fn (): Response => $this->runMiddleware(RequirePermission::class, self::request(), 'posts:delete'))->getMessage());
        self::assertSame('Action non autorisée.', self::denialOf(fn (): Response => $this->runMiddleware(AuthorizeAction::class, self::request(), 'posts:delete'))->getMessage());
    }

    /**
     * A middleware built without a translator keeps Laravel's English message.
     *
     * @return void
     */
    public function testWithoutATranslatorTheMessageIsLaravelsEnglish(): void
    {
        $this->actingAs($this->seedGrantedUser());

        $denial = self::denialOf(static fn (): mixed => (new RequireRole)->handle(self::request(), self::passThrough(), 'auditor'));

        self::assertSame('This action is unauthorized.', $denial->getMessage());
    }

    /**
     * A middleware the container resolves words the unauthenticated response
     * with the translator's line, in its current locale.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware>  $middleware
     * @param  string  $names
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    #[TestWith([RequireRole::class, 'admin'])]
    #[TestWith([RequirePermission::class, 'posts:create'])]
    #[TestWith([AuthorizeAction::class, 'posts:create'])]
    public function testTheUnauthenticatedMessageIsTranslatedInTheCurrentLocale(string $middleware, string $names): void
    {
        $this->inFrench();

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Non authentifié.');

        $this->runMiddleware($middleware, self::request(), $names);
    }

    /**
     * Without a translator, or when the translator has no line for the key, the
     * unauthenticated response keeps Laravel's English message.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function testWithoutALineTheUnauthenticatedMessageIsLaravelsEnglish(): void
    {
        $missing = self::createStub(Translator::class);
        $missing->method('get')->willReturnArgument(0);

        foreach ([new RequireRole, new RequirePermission($missing)] as $middleware) {
            try {
                $middleware->handle(self::request(), self::passThrough(), 'admin');
                self::fail($middleware::class . ' admitted the request.');
            } catch (AuthenticationException $exception) {
                self::assertSame('Unauthenticated.', $exception->getMessage());
            }
        }
    }

    /**
     * An allow whose authentication requirement alone is unmet raises the
     * insufficient authentication exception from the `permission` and
     * `authorize` middleware, so the application can map it to a step-up.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function testAnUnmetRequirementRaisesInsufficientAuthentication(): void
    {
        $policy = EvaluationPolicy::fromArray(['name' => 'step-up', 'statements' => [[
            'effect'     => 'allow',
            'actions'    => ['reports:export'],
            'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]],
        ]]]);

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
        $this->app?->forgetInstance('authorization');
        $this->app?->forgetInstance(AuthorizationManager::class);
        Authorization::clearResolvedInstances();

        $this->actingAs($this->seedGrantedUser());

        foreach ([new RequirePermission, new AuthorizeAction] as $middleware) {
            try {
                $middleware->handle(self::request(), self::passThrough(), 'reports:export');
                self::fail($middleware::class . ' admitted the request.');
            } catch (InsufficientAuthenticationException $exception) {
                self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $exception->getReason());
                self::assertSame(['multifactor'], $exception->requirements()[0]->unmet);
            }
        }
    }

    /**
     * Once the package refuses, a route through each of the package's
     * middleware refuses by the middleware's own guard before the route runs.
     *
     * @return void
     */
    public function testARouteThroughEachMiddlewareRefusesOnceThePackageRefuses(): void
    {
        $router = $this->container()->make('router');

        foreach (['role:editor', 'permission:posts:read', 'authorize:posts:read'] as $middleware) {
            $router->get('/refused/' . \strtok($middleware, ':'), static fn (): never => self::fail('The route ran.'))->middleware($middleware);
        }

        $this->refuseThePackage();
        $this->withoutExceptionHandling();

        $this->assertEachRefused([
            'handle through role'       => fn () => $this->get('/refused/role'),
            'handle through permission' => fn () => $this->get('/refused/permission'),
            'handle through authorize'  => fn () => $this->get('/refused/authorize'),
        ]);
    }

    /**
     * Give the translator French lines for the package and switch to French.
     *
     * @return void
     */
    private function inFrench(): void
    {
        $translator = $this->app?->make(Translator::class);
        self::assertInstanceOf(TranslatorImplementation::class, $translator);

        $translator->addLines(['authorization.denied' => 'Action non autorisée.', 'authorization.unauthenticated' => 'Non authentifié.'], 'fr', 'authorization');
        $translator->setLocale('fr');
    }

    /**
     * Create a user holding the `admin` role and the `posts:create` permission.
     *
     * @return \Tests\Feature\Stubs\AuthenticatableIdentity
     */
    private function seedGrantedUser(): AuthenticatableIdentity
    {
        $user = AuthenticatableIdentity::create(['id' => 'signed-in']);
        $user->assignRole(Role::create(['name' => 'admin', 'guard' => 'web']));
        $user->givePermission(Permission::create(['name' => 'posts:create', 'guard' => 'web']));

        return $user;
    }
}
