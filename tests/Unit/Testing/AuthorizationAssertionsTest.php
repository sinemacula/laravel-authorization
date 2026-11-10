<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Illuminate\Auth\Access\AuthorizationException as LaravelAuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\Middleware\Authorize;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Testing\Concerns\AuthorizationAssertions;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Tests for the shipped testing helpers trait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationManager::class)]
#[CoversTrait(AuthorizationAssertions::class)]
final class AuthorizationAssertionsTest extends TestCase
{
    use AuthorizationAssertions;

    /**
     * `assertCan` passes when the principal holds the permission.
     *
     * @return void
     */
    public function testAssertCanPassesWhenAllowed(): void
    {
        Permission::create(['id' => 'c2d9b0b4-d6db-4c09-8e1c-3cc9a9afff14', 'name' => 'docs:view', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => 'c04bbc1e-a3f1-4a00-8a37-5b6ca2de6a88']);
        $user->givePermission('docs:view');

        $this->assertCan($user, 'docs:view');
    }

    /**
     * `assertCan` fails when denied, with a message that carries the decision's
     * explanation: the verdict, its reason and stage, and every trace step.
     *
     * @return void
     */
    public function testAssertCanFailsWithTraceOnDeny(): void
    {
        $user = StubIdentity::create(['id' => '9c92e0cb-686f-4347-8ca8-9033eed62375']);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage(
            "Failed asserting that the principal can perform 'docs:view'.\nDecision:\n"
            . "DENY (no_match: no statement or permission names it) at the implicit stage.\n"
            . "  [guardrail] guardrails: uncapped\n  [boundary] boundaries: uncapped\n  [session] session caps: uncapped\n  [allow] permission: not_held",
        );

        $this->assertCan($user, 'docs:view');
    }

    /**
     * `assertCannot` passes when the principal is denied.
     *
     * @return void
     */
    public function testAssertCannotPassesWhenDenied(): void
    {
        $user = StubIdentity::create(['id' => '10e3747c-3a23-4c42-8245-4f1f6ce2183d']);

        $this->assertCannot($user, 'docs:delete');
    }

    /**
     * `assertCannot` fails when the principal is allowed, with a message that
     * carries the decision's explanation.
     *
     * @return void
     */
    public function testAssertCannotFailsWhenAllowed(): void
    {
        Permission::create(['id' => 'bf869580-a8d2-4a40-87c7-de6a9d559418', 'name' => 'docs:delete', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '34f13826-645d-4917-81b2-44e93dbf1863']);
        $user->givePermission('docs:delete');

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage(
            "Failed asserting that the principal cannot perform 'docs:delete'.\nDecision:\nALLOW at the allow stage by permission \"docs:delete\".\n"
            . "  [guardrail] guardrails: uncapped\n  [boundary] boundaries: uncapped\n  [session] session caps: uncapped\n  [allow] permission \"docs:delete\": held\n"
            . '  evidence: not recorded (explain mode off)',
        );

        $this->assertCannot($user, 'docs:delete');
    }

    /**
     * `assertHasRole` passes when the role is assigned.
     *
     * @return void
     */
    public function testAssertHasRolePassesWhenAssigned(): void
    {
        Role::create(['id' => 'db35d033-4ec2-49d6-86f2-2e35abb79258', 'name' => 'editor', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '273e3845-88e8-4f96-8c2c-1da012769254']);
        $user->assignRole('editor');

        $this->assertHasRole($user, 'editor');
    }

    /**
     * `assertHasRole` fails when the role is not assigned.
     *
     * @return void
     */
    public function testAssertHasRoleFailsWhenMissing(): void
    {
        $user = StubIdentity::create(['id' => '76018d54-4b6b-4111-8f36-0211bbf0809a']);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/Failed asserting that the principal has role \'admin\'/');

        $this->assertHasRole($user, 'admin');
    }

    /**
     * `assertHasPermission` passes when the permission is held.
     *
     * @return void
     */
    public function testAssertHasPermissionPassesWhenHeld(): void
    {
        Permission::create(['id' => '6d4b70d0-3fed-4b56-8f2e-ee0d7dd8c9cc', 'name' => 'docs:edit', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '6160c26b-9f8d-437b-8e39-bc3fcef72076']);
        $user->givePermission('docs:edit');

        $this->assertHasPermission($user, 'docs:edit');
    }

    /**
     * `assertHasPermission` fails when the permission is not held.
     *
     * @return void
     */
    public function testAssertHasPermissionFailsWhenMissing(): void
    {
        $user = StubIdentity::create(['id' => 'f67a151d-b31d-4c6c-8d79-097b54709b8d']);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/Failed asserting that the principal has permission \'docs:edit\'/');

        $this->assertHasPermission($user, 'docs:edit');
    }

    /**
     * `actingAsIdentity` swaps the resolver so the facade works without
     * explicit `for()`.
     *
     * @return void
     */
    public function testActingAsIdentitySwapsResolver(): void
    {
        Permission::create(['id' => 'f663ff0d-9a15-49bd-8234-d30ac5b91f73', 'name' => 'docs:publish', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '5f5924a2-a361-4d9a-8ea6-f24ecbc25de1']);
        $user->givePermission('docs:publish');

        // Before swap, anonymous principal is denied.
        self::assertFalse(Authorization::can('docs:publish'));

        $this->actingAsIdentity($user);

        // After swap, the facade resolves the swapped principal.
        self::assertTrue(Authorization::can('docs:publish'));
    }

    /**
     * `actingAsIdentity` makes the identity its own subject, in the tenant
     * given or in none, and the tenant reaches the tenant scope.
     *
     * @return void
     */
    public function testActingAsIdentityCarriesTheTenant(): void
    {
        $tenant = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $user   = StubIdentity::create(['id' => '0b7d3e1c-4f2a-4c8e-9a6b-1d2e3f4a5b6c']);

        Role::create(['name' => 'platform', 'guard' => 'web']);
        Role::create(['name' => 'owned', 'guard' => 'web', 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => 'tenant-a']);

        $this->actingAsIdentity($user);

        $subject = Authorization::currentSubject();

        self::assertNotNull($subject);
        self::assertSame($user, $subject->subject);
        self::assertSame($user, $subject->identity);
        self::assertNull($subject->tenant);
        self::assertSame(['platform'], Role::query()->pluck('name')->all());

        $this->actingAsIdentity($user, $tenant);

        self::assertSame($tenant, Authorization::currentSubject()?->tenant);
        self::assertSame(['owned', 'platform'], Role::query()->orderBy('name')->pluck('name')->all());
    }

    /**
     * `actingAsSubject` resolves the subject given, and a user Laravel's Gate
     * hands over is decided about in the subject's tenant and application.
     *
     * @return void
     */
    public function testActingAsSubjectTranslatesTheGatesUserIntoItsRequest(): void
    {
        $tenant  = new \stdClass;
        $user    = StubIdentity::create(['id' => '6c5b4a3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d']);
        $subject = new Subject($user, null, $tenant, 'admin', 'web');

        $this->actingAsSubject($subject);

        self::assertSame($subject, Authorization::currentSubject());
        self::assertSame($subject, Authorization::forUser($user)->currentSubject());

        $other      = new \stdClass;
        $translated = Authorization::forUser($other)->currentSubject();

        self::assertNotNull($translated);
        self::assertSame($other, $translated->subject);
        self::assertSame($tenant, $translated->tenant);
        self::assertSame('admin', $translated->application);
    }

    /**
     * When the Gate hands over the identity signed in behind the acting
     * subject, it decides about the subject's principal, as the facade does,
     * not about the identity.
     *
     * @return void
     */
    public function testTheGateDecidesAboutThePrincipalOfTheSignedInIdentity(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make('config');
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        (new AuthorizationServiceProvider($this->container()))->boot();

        Permission::create(['name' => 'posts:create', 'guard' => 'web']);

        $principal = StubIdentity::create(['id' => '3a8f1c2e-5b7d-4e9a-8c6f-2d1b0a9e8f7c']);
        $identity  = AuthenticatableIdentity::create(['id' => '7e2d4c6b-9a1f-4b3e-8d5c-1f0e9a8b7c6d']);
        $subject   = new Subject($principal, $identity, null, 'admin', 'web');

        $principal->givePermission('posts:create');

        $this->actingAsSubject($subject);

        self::assertSame($subject, Authorization::forUser($identity)->currentSubject());
        self::assertTrue(Gate::forUser($identity)->allows('posts:create'));
        self::assertFalse($identity->hasPermission('posts:create'));
    }

    /**
     * When the Gate hands over the acting subject's principal or identity, the
     * subject keeps its session, so a requirement the checker meets is met
     * through the Gate as it is through the facade.
     *
     * @return void
     */
    public function testTheGateAndTheFacadeAgreeOnARequirementForThePrincipal(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make('config');
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        (new AuthorizationServiceProvider($this->container()))->boot();

        Permission::create(['name' => 'posts:create', 'guard' => 'web']);

        $principal = StubIdentity::create(['id' => '1d3f5b7a-9c2e-4a6b-8d0f-3e5a7c9b1d2f']);
        $identity  = AuthenticatableIdentity::create(['id' => '2e4a6c8b-0d3f-4b7c-9e1a-4f6b8d0c2e3a']);

        $principal->attachPolicy(Policy::create([
            'id'       => '3f5b7d9c-1e4a-4c8d-8f2b-5a7c9e1d3f4b',
            'name'     => 'step-up-create',
            'document' => ['statements' => [[
                'effect'     => 'allow',
                'actions'    => ['posts:create'],
                'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]],
            ]]],
        ]));

        $this->app?->instance(AuthenticationRequirementChecker::class, new StubRequirementChecker(RequirementResult::met()));
        $this->actingAsSubject(new Subject($principal, $identity, null, 'admin', 'web', session: 'session-1'));

        self::assertTrue(Authorization::can('posts:create'));
        self::assertSame('session-1', Authorization::forUser($principal)->currentSubject()?->session);
        self::assertTrue(Gate::forUser($principal)->allows('posts:create'));
        self::assertTrue(Gate::forUser($identity)->allows('posts:create'));
    }

    /**
     * After `actingAsIdentity`, with no user signed in, the Gate's user is the
     * identity: `Gate::allows()`, `@can` and `can:` answer as the facade does,
     * for an allow and for a deny, and decide about the identity.
     *
     * @return void
     */
    public function testTheGateAndTheFacadeAgreeAfterActingAsIdentity(): void
    {
        $this->bootWithPermissionEnum();

        $user = StubIdentity::create(['id' => '8b1d3f5a-7c9e-4b2d-a4f6-0e2c4a6b8d1f']);
        $user->givePermission('posts:create');

        $this->actingAsIdentity($user);

        $this->assertGuest();
        $this->assertTheGateAgreesWithTheFacade('posts:create', true);
        $this->assertTheGateAgreesWithTheFacade('posts:delete', false);
        self::assertEquals(Reference::of($user), $this->lastPrincipal());
    }

    /**
     * After `actingAsSubject`, with no user signed in, the Gate's user is the
     * subject's identity, which the resolver maps to the subject: the Gate
     * decides a declared ability about the principal, as the facade does, not
     * about the identity, and hands the identity to an undeclared one.
     *
     * @return void
     */
    public function testTheGateAndTheFacadeAgreeAfterActingAsSubject(): void
    {
        $this->bootWithPermissionEnum();

        $principal = StubIdentity::create(['id' => '9c2e4a6b-8d0f-4c3e-b5a7-1f3d5b7c9e2a']);
        $identity  = AuthenticatableIdentity::create(['id' => '0d3f5b7c-9e1a-4d4f-86b8-2a4c6e8d0f3b']);

        $principal->givePermission('posts:create');

        Gate::define('reports:inspect', static fn (object $user): bool => $user === $identity);

        $this->actingAsSubject(new Subject($principal, $identity, null, 'admin', 'web'));

        $this->assertGuest();
        self::assertTrue(Gate::allows('reports:inspect'));
        $this->assertTheGateAgreesWithTheFacade('posts:create', true);
        $this->assertTheGateAgreesWithTheFacade('posts:delete', false);
        self::assertFalse($identity->hasPermission('posts:create'));
        self::assertEquals(Reference::of($principal), $this->lastPrincipal());
    }

    /**
     * A subject without an identity makes its principal the Gate's user, so the
     * Gate still decides about the subject rather than a guest.
     *
     * @return void
     */
    public function testASubjectWithoutAnIdentityMakesItsPrincipalTheGatesUser(): void
    {
        $this->bootWithPermissionEnum();

        $principal = StubIdentity::create(['id' => '1e4a6c8d-0f2b-4e5a-97c9-3b5d7f9e1a4c']);
        $principal->givePermission('posts:create');

        Gate::define('reports:inspect', static fn (object $user): bool => $user === $principal);

        $this->actingAsSubject(new Subject($principal));

        self::assertTrue(Gate::allows('reports:inspect'));
        $this->assertTheGateAgreesWithTheFacade('posts:create', true);
        self::assertEquals(Reference::of($principal), $this->lastPrincipal());
    }

    /**
     * Acting again moves the Gate's user to the new subject, and the Gate keeps
     * the abilities defined before either helper ran.
     *
     * @return void
     */
    public function testActingAgainMovesTheGatesUserAndKeepsItsAbilities(): void
    {
        $this->bootWithPermissionEnum();

        $first  = StubIdentity::create(['id' => '2f5b7d9e-1a3c-4f6b-a8d0-4c6e8a0f2b5d']);
        $second = StubIdentity::create(['id' => '3a6c8e0f-2b4d-4a7c-b9e1-5d7f9b1c3e6a']);

        Gate::define('reports:export', static fn (object $user): bool => $user === $second);

        $first->givePermission('posts:create');

        $this->actingAsIdentity($first);

        $this->assertTheGateAgreesWithTheFacade('posts:create', true);
        self::assertFalse(Gate::allows('reports:export'));

        $this->actingAsIdentity($second);

        $this->assertTheGateAgreesWithTheFacade('posts:create', false);
        self::assertTrue(Gate::allows('reports:export'));
    }

    /**
     * `assertCan` includes the resource in its failure message when one is
     * supplied.
     *
     * @return void
     */
    public function testAssertCanIncludesResourceInFailureMessage(): void
    {
        $user = StubIdentity::create(['id' => '53e9833c-b3d7-4ecf-845e-616b486a1677']);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/on resource \'post:42\'/');

        $this->assertCan($user, 'posts:edit', 'post:42');
    }

    /**
     * `assertCan` passes when allowed via policy with resource context, which
     * the check reads under `input`.
     *
     * @return void
     */
    public function testAssertCanPassesWithResourceAndContext(): void
    {
        $user = StubIdentity::create(['id' => 'e95a40aa-3f8b-4137-8d8a-71879a3c0dcb']);

        $user->attachPolicy(Policy::create([
            'id'       => 'd9b1e409-7edc-4807-879c-6301100ecd3f',
            'name'     => 'scoped-allow',
            'document' => [
                'statements' => [[
                    'effect'     => 'allow',
                    'actions'    => ['posts:edit'],
                    'resources'  => ['post:42'],
                    'conditions' => ['eq' => ['input.tenant' => 'org-1']],
                ]],
            ],
        ]));

        $this->assertCan($user, 'posts:edit', 'post:42', ['tenant' => 'org-1']);
        $this->assertCannot($user, 'posts:edit', 'post:42', ['tenant' => 'org-2']);
        $this->assertCannot($user, 'posts:edit', 'post:42', ['input' => ['tenant' => 'org-1']]);
    }

    /**
     * `assertCan` and `assertCannot` take any resource a check takes: a `(type,
     * id)` pair names the record as `type:id`, as a string does.
     *
     * @return void
     */
    public function testAssertionsTakeATypeAndIdPair(): void
    {
        $user = StubIdentity::create(['id' => '0d6f2b8a-41c7-4e3b-9a5d-6c8e1f2a3b4d']);

        $user->attachPolicy(Policy::create([
            'id'       => '5a1c9e7b-3d2f-4b6a-8e0c-9f1d2a3b4c5e',
            'name'     => 'pair-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:edit'], 'resources' => ['post:42']],
                ],
            ],
        ]));

        $this->assertCan($user, 'posts:edit', ['post', 42]);
        $this->assertCannot($user, 'posts:edit', ['post', 43]);
    }

    /**
     * `assertCan` names a saved model in its failure message by the reference
     * the check made of it, `morphClass:key`.
     *
     * @return void
     */
    public function testAssertCanDescribesAModelByItsReference(): void
    {
        $user   = StubIdentity::create(['id' => '8b3e1d5f-7a2c-4f9e-b6d4-2c1a0e9f8d7b']);
        $target = StubTenant::create(['id' => 'tenant-described', 'name' => 'Described']);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Failed asserting that the principal can perform \'posts:edit\' on resource \'' . $target->getMorphClass() . ':tenant-described\'.');

        $this->assertCan($user, 'posts:edit', $target);
    }

    /**
     * A resource that cannot be identified is described by nothing in the
     * failure message, and the check it names is denied as unresolved, so
     * `assertCannot` passes on it.
     *
     * @return void
     */
    public function testAnUnidentifiableResourceIsDescribedByNothing(): void
    {
        Permission::create(['id' => '2e4c6a8b-0d1f-4a3c-9e5b-7d9f1b3d5f7a', 'name' => 'docs:view', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '4f6a8c0e-2b4d-4f6a-8c0e-2b4d6f8a0c2e']);
        $user->givePermission('docs:view');

        $this->assertCannot($user, 'docs:view', 42);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage(
            "Failed asserting that the principal can perform 'docs:view'.\nDecision:\n"
            . 'DENY (resource_unresolved: the resource cannot be identified) at the resource stage.',
        );

        $this->assertCan($user, 'docs:view', new StubIdentity);
    }

    /**
     * `assertCan` and `assertCannot` are public, so a helper outside the test
     * case that uses the trait can call them on it.
     *
     * @return void
     */
    public function testAssertCanAndAssertCannotArePublic(): void
    {
        self::assertTrue((new \ReflectionMethod(self::class, 'assertCan'))->isPublic());
        self::assertTrue((new \ReflectionMethod(self::class, 'assertCannot'))->isPublic());
    }

    /**
     * Declare the stub permission enum and boot the provider again, so the Gate
     * hook answers its cases, and fake the decision event so each decision's
     * principal is observable.
     *
     * @return void
     */
    private function bootWithPermissionEnum(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make('config');
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        (new AuthorizationServiceProvider($this->container()))->boot();

        Permission::create(['name' => 'posts:create', 'guard' => 'web']);
        Permission::create(['name' => 'posts:delete', 'guard' => 'web']);

        Event::fake([DecisionEvaluated::class]);
    }

    /**
     * Return the reference to the principal of the last decision evaluated.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    private function lastPrincipal(): ?Reference
    {
        /** @var \SineMacula\Laravel\Authorization\Events\DecisionEvaluated|null $decision */
        $decision = Event::dispatched(DecisionEvaluated::class)->last()[0] ?? null;

        return $decision?->subject;
    }

    /**
     * Assert the facade, `Gate::allows()`, `@can` and the `can:` middleware all
     * answer the action as expected for the acting subject.
     *
     * @param  string  $action
     * @param  bool  $expected
     * @return void
     */
    private function assertTheGateAgreesWithTheFacade(string $action, bool $expected): void
    {
        $verdict = $expected ? 'allowed' : 'refused';

        self::assertSame($expected, Authorization::can($action), "The facade answered wrongly on {$action}.");
        self::assertSame($expected, Gate::allows($action), "The Gate answered wrongly on {$action}.");
        self::assertSame($verdict, \trim(Blade::render("@can('{$action}') allowed @else refused @endcan")), "@can answered wrongly on {$action}.");
        self::assertSame($expected, $this->canMiddlewareAdmits($action), "can: answered wrongly on {$action}.");
    }

    /**
     * Determine whether Laravel's `can:` middleware admits a request for the
     * action: a refusal of either kind admits nothing.
     *
     * @param  string  $action
     * @return bool
     */
    private function canMiddlewareAdmits(string $action): bool
    {
        /** @var \Illuminate\Auth\Middleware\Authorize $middleware */
        $middleware = $this->app?->make(Authorize::class);

        try {
            $middleware->handle(Request::create('/posts'), static fn (): Response => new Response('ok'), $action);
        } catch (AuthenticationException|LaravelAuthorizationException) {
            return false;
        }

        return true;
    }
}
