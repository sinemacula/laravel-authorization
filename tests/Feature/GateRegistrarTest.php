<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\Access\AuthorizationException as LaravelAuthorizationException;
use Illuminate\Auth\Middleware\Authorize;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\DeclaredAbilities;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\ReportsEveryDecision;
use Tests\Feature\Stubs\AllowingLaravelPolicy;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\DenyingLaravelPolicy;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubPermissionProvider;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\TestCase;

/**
 * Feature coverage for the Gate hook the registrar registers: which abilities
 * it answers and which fall through to Laravel, its precedence over the
 * application's defines, policy classes and before-callbacks, whom a check is
 * about, the switch that turns it off, and how the positional arguments become
 * the resource the evaluator sees.
 *
 * An argument that cannot be identified as a resource (an unsaved model, a
 * model without a usable key, a number, a boolean, a list that is not a `(type,
 * id)` pair or a plain object) is denied by the decision at the resource stage
 * as an unresolved resource, without consulting any policy or RBAC grant, so it
 * can never be mistaken for a check about no resource at all. A null argument
 * means no resource; strings, saved models, model classes, `(type, id)` pairs,
 * resource-contract objects and stringable objects are forwarded as their
 * references, a model's with the tenant its resolver names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GateRegistrar::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(AuthorizationManager::class)]
final class GateRegistrarTest extends TestCase
{
    use ReadsDispatchedEvents, ReportsEveryDecision;

    /**
     * Boot the provider with the demo permission enum so the Gate asks the
     * package about its cases in each test, and fake the decision event so
     * every evaluation is observable.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->reportEveryDecision();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        // Register a morph alias so model identifiers are short and exact.
        Relation::morphMap(['stub' => StubIdentity::class]);

        (new AuthorizationServiceProvider($this->container()))->boot();

        Event::fake([DecisionEvaluated::class]);
    }

    /**
     * Reset morph map state after each test so cross-test leakage cannot mask a
     * regression.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * An unsaved model has no key, so it cannot be identified as a resource and
     * the Gate refuses it as an unresolved resource.
     *
     * @return void
     */
    public function testUnsavedModelIsRefusedAsUnresolved(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(new StubIdentity, $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * A model whose key is the empty string cannot be identified as a resource,
     * so the Gate refuses it as an unresolved resource.
     *
     * @return void
     */
    public function testModelWithEmptyStringKeyIsRefusedAsUnresolved(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(new StubIdentity(['id' => '']), $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * An integer argument is not a resource identifier, so the Gate refuses it
     * as an unresolved resource.
     *
     * @return void
     */
    public function testIntegerArgumentIsRefusedAsUnresolved(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(42, $user);
        $this->assertGateRefusesUnidentifiedArgument(0, $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * A float argument is not a resource identifier, so the Gate refuses it as
     * an unresolved resource.
     *
     * @return void
     */
    public function testFloatArgumentIsRefusedAsUnresolved(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(4.2, $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * A boolean argument is not a resource identifier, so the Gate refuses it
     * as an unresolved resource, whichever value it carries.
     *
     * @return void
     */
    public function testBooleanArgumentIsRefusedAsUnresolved(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(true, $user);
        $this->assertGateRefusesUnidentifiedArgument(false, $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * A list array at index zero that is not a `(type, id)` pair (empty, of
     * another length, or with an empty or non-string type, or an id that is
     * empty, boolean or not a scalar) is neither a context map nor a resource,
     * so the Gate refuses it as an unresolved resource.
     *
     * @return void
     */
    public function testListArrayArgumentThatIsNotAPairIsRefusedAsUnresolved(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument([], $user);
        $this->assertGateRefusesUnidentifiedArgument(['post'], $user);
        $this->assertGateRefusesUnidentifiedArgument(['arn:post:42', 'arn:post:43', 'arn:post:44'], $user);
        $this->assertGateRefusesUnidentifiedArgument(['', 42], $user);
        $this->assertGateRefusesUnidentifiedArgument([42, 42], $user);
        $this->assertGateRefusesUnidentifiedArgument(['post', ''], $user);
        $this->assertGateRefusesUnidentifiedArgument(['post', true], $user);
        $this->assertGateRefusesUnidentifiedArgument(['post', null], $user);
        $this->assertGateRefusesUnidentifiedArgument(['post', ['42']], $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * A `(type, id)` pair at index zero names one record of the type, as
     * `type:id`, whether the id is a string or a number.
     *
     * @return void
     */
    public function testTypeAndIdPairIsIdentifiedAsTheRecord(): void
    {
        $this->actAsPrincipalAllowedOn('post:42');

        self::assertTrue(Gate::allows('posts:create', [['post', 42]]));
        self::assertTrue(Gate::allows('posts:create', [['post', '42']]));
        self::assertFalse(Gate::allows('posts:create', [['post', 43]]));
        self::assertSame(['post:42', 'post:42', 'post:43'], $this->evaluatedResources());
    }

    /**
     * Laravel spreads an argument array, so `Gate::allows('x', ['post', 42])`
     * reaches the callback as two positional arguments, which name the record
     * they spell: a deny on `post:42` refuses it despite an allow on every
     * resource, and another record of the type is still allowed.
     *
     * @return void
     */
    public function testSpreadTypeAndIdArgumentsNameTheRecord(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'all-but-post-42',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['*']],
                    ['effect' => 'deny', 'actions' => ['posts:create'], 'resources' => ['post:42']],
                ],
            ],
        ]));

        $this->actAs($user);

        self::assertFalse(Gate::allows('posts:create', ['post', 42]));
        self::assertSame(DecisionReason::EXPLICIT_DENY, Authorization::lastDecision()?->reason);
        self::assertTrue(Gate::allows('posts:create', ['post', 43]));
        self::assertSame(['post:42', 'post:43'], $this->evaluatedResources());
    }

    /**
     * A context map before or after the spread `(type, id)` arguments, or
     * context passed by name after them, is merged into the context, a later
     * map's key over an earlier one's, and not counted as part of the resource,
     * so the check is still about the record.
     *
     * @return void
     */
    public function testContextBesideSpreadTypeAndIdArgumentsIsMerged(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'post-42-in-org-1',
            'document' => [
                'statements' => [[
                    'effect'     => 'allow',
                    'actions'    => ['posts:create'],
                    'resources'  => ['post:42'],
                    'conditions' => ['eq' => ['input.tenant' => 'org-1']],
                ]],
            ],
        ]));

        $this->actAs($user);

        self::assertTrue(Gate::allows('posts:create', [['tenant' => 'org-1'], 'post', 42]));
        self::assertTrue(Gate::allows('posts:create', ['post', 42, ['tenant' => 'org-1']]));
        self::assertTrue(Gate::allows('posts:create', ['post', 42, 'tenant' => 'org-1']));
        self::assertTrue(Gate::allows('posts:create', [['tenant' => 'org-2'], 'post', 42, ['tenant' => 'org-1']]));
        self::assertFalse(Gate::allows('posts:create', ['post', 42, ['tenant' => 'org-2']]));
        self::assertSame(['post:42', 'post:42', 'post:42', 'post:42', 'post:42'], $this->evaluatedResources());
        self::assertSame(['input.tenant'], $this->decisions()[4]->keys);
        self::assertFalse($this->decisions()[4]->isAllowed());
    }

    /**
     * Three positional resource arguments, or a model followed by a stray
     * value, name no resource the check can identify, so the Gate refuses them
     * as an unresolved resource rather than silently dropping a value.
     *
     * @return void
     */
    public function testMoreResourceArgumentsThanAPairAreRefusedAsUnresolved(): void
    {
        $user   = $this->actAsFullyPermittedPrincipal();
        $target = StubIdentity::create(['id' => 'target-1']);

        self::assertFalse(Gate::allows('posts:create', ['post', 42, 'extra']));
        $this->assertRefusalRecorded(0, $user);

        self::assertFalse(Gate::allows('posts:create', [$target, 99]));
        $this->assertRefusalRecorded(1, $user);

        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * A model class names its type alone, as `morphClass:*`, so a statement on
     * the type covers it and one on a single record does not.
     *
     * @return void
     */
    public function testModelClassIsIdentifiedAsItsType(): void
    {
        $this->actAsPrincipalAllowedOn('stub:*');

        $recordOnly = StubIdentity::create(['id' => (string) Str::uuid()]);

        $recordOnly->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'record-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['stub:target-1']],
                ],
            ],
        ]));

        self::assertTrue(Gate::allows('posts:create', [StubIdentity::class]));
        self::assertFalse(Gate::forUser($recordOnly)->allows('posts:create', [StubIdentity::class]));
        self::assertSame(['stub:*', 'stub:*'], $this->evaluatedResources());
    }

    /**
     * A plain object without `__toString` cannot be identified as a resource,
     * so the Gate refuses it as an unresolved resource.
     *
     * @return void
     */
    public function testPlainObjectArgumentIsRefusedAsUnresolved(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(new \stdClass, $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * The refusal also applies when the Gate is dispatched for an explicit user
     * rather than the resolved principal, and the recorded decision names the
     * Gate user rather than the resolved principal.
     *
     * @return void
     */
    public function testUnidentifiableArgumentIsRefusedForExplicitUser(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        // Resolve a different principal so the recorded decision can only name
        // the Gate user if the callback scoped the manager to it.
        $this->actAs(StubIdentity::create(['id' => (string) Str::uuid()]));

        self::assertFalse(Gate::forUser($user)->allows('posts:create', [42]));
        $this->assertRefusalRecorded(0, $user);

        self::assertTrue(Gate::forUser($user)->allows('posts:create', [null]));
        self::assertSame([null, null], $this->evaluatedResources());
        self::assertEquals(Reference::of($user), $this->decisions()[1]->subject);
        self::assertEquals([$this->wildcardAllowReference()], Authorization::lastDecision()?->statements);
    }

    /**
     * The context supplied alongside an unidentifiable argument is never
     * carried on the recorded refusal's event, as it is not for any other check
     * (AUTHZ-15.4).
     *
     * @return void
     */
    public function testUnidentifiableArgumentRefusalNeverCarriesTheContext(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        self::assertFalse(Gate::allows('posts:create', [42, ['tenant' => 'org-7']]));
        $this->assertRefusalRecorded(0, $user, ['tenant' => 'org-7']);
    }

    /**
     * A null argument means no resource: a wildcard-resource allow applies.
     *
     * @return void
     */
    public function testNullArgumentAppliesWildcardResourceAllow(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'wildcard-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create']],
                ],
            ],
        ]));

        self::assertTrue(Gate::allows('posts:create', [null]));
        self::assertSame([null], $this->evaluatedResources());
        self::assertEquals([$this->wildcardAllowReference()], Authorization::lastDecision()?->statements);
    }

    /**
     * A null argument means no resource: an allow scoped to particular
     * resources does not apply to it.
     *
     * @return void
     */
    public function testNullArgumentDoesNotApplyResourceScopedAllow(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'scoped-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['arn:post:42']],
                ],
            ],
        ]));

        self::assertFalse(Gate::allows('posts:create', [null]));
        self::assertSame([null], $this->evaluatedResources());
        self::assertSame(DecisionReason::NO_MATCH, Authorization::lastDecision()?->reason);
    }

    /**
     * A string argument passes through unchanged as the resource identifier.
     *
     * @return void
     */
    public function testStringArgumentPassesThrough(): void
    {
        $this->actAsPrincipalAllowedOn('arn:post:42');

        self::assertTrue(Gate::allows('posts:create', ['arn:post:42']));
        self::assertFalse(Gate::allows('posts:create', ['arn:post:99']));
        self::assertSame(['arn:post:42', 'arn:post:99'], $this->evaluatedResources());
    }

    /**
     * A saved model is identified as `{morphClass}:{key}`.
     *
     * @return void
     */
    public function testSavedModelIsIdentifiedByMorphClassAndKey(): void
    {
        $target = StubIdentity::create(['id' => 'target-1']);

        $this->actAsPrincipalAllowedOn('stub:target-1');

        self::assertTrue(Gate::allows('posts:create', [$target]));
        self::assertSame(['stub:target-1'], $this->evaluatedResources());
    }

    /**
     * A saved model's tenant is the one the bound resource tenant resolver
     * names, and it reaches the decision: with no tenant active, a tenant-owned
     * model is out of scope and denied as `tenant_scope` before any policy is
     * read, unless the subject holds the permission platform-wide.
     *
     * @return void
     */
    public function testSavedModelCarriesTheTenantItsResolverNames(): void
    {
        $resolver = new FixedResourceTenantResolver(new Reference('org', 'org-1'));
        $target   = StubIdentity::create(['id' => 'target-1']);

        $this->app?->instance(ResourceTenantResolver::class, $resolver);

        // Act as the platform-wide holder first, so the scoped principal below
        // is the request's subject and the holder is the Gate user's.
        $holder = $this->actAsFullyPermittedPrincipal();

        $this->actAsPrincipalAllowedOn('stub:target-1');

        self::assertFalse(Gate::allows('posts:create', [$target]));
        self::assertSame([$target], $resolver->asked);

        $denial = $this->decisions()[0];

        self::assertSame('stub:target-1', $denial->resource);
        self::assertSame(DecisionReason::TENANT_SCOPE, $denial->reason);
        self::assertSame(DecisionStage::TENANT, Authorization::lastDecision()?->stage);
        self::assertSame([], Authorization::lastDecision()->trace);

        self::assertTrue(Gate::forUser($holder)->allows('posts:create', [$target]));
        self::assertSame(['stub:target-1', 'stub:target-1'], $this->evaluatedResources());
        self::assertEquals(Reference::of($holder), $this->decisions()[1]->subject);
    }

    /**
     * A resource reference passed to the Gate is used as given, its tenant
     * included.
     *
     * @return void
     */
    public function testResourceReferenceIsUsedAsGiven(): void
    {
        $this->actAsPrincipalAllowedOn('invoice:7');

        self::assertTrue(Gate::allows('posts:create', [ResourceReference::record('invoice', '7')]));
        self::assertFalse(Gate::allows('posts:create', [ResourceReference::record('invoice', '7', new Reference('org', 'org-1'))]));
        self::assertSame(['invoice:7', 'invoice:7'], $this->evaluatedResources());
        self::assertSame(DecisionReason::TENANT_SCOPE, Authorization::lastDecision()?->reason);
    }

    /**
     * An Eloquent model implementing the resource contract is identified by
     * `toResourceReference()`, both when it has a key of its own and when it
     * has none, and the resource tenant resolver is not asked about it.
     *
     * @return void
     */
    public function testEloquentModelImplementingResourceContractUsesItsReference(): void
    {
        $resolver = new FixedResourceTenantResolver(new Reference('org', 'org-1'));

        $this->app?->instance(ResourceTenantResolver::class, $resolver);

        $this->actAsPrincipalAllowedOn('document:contract-7');

        $resource = new class extends Model implements AuthorizableResource {
            /** @var string|null Backing table. */
            protected $table = 'stub_identities';

            /**
             * Return the reference to the resource.
             *
             * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
             */
            #[\Override]
            public function toResourceReference(): ResourceReference
            {
                return ResourceReference::record('document', 'contract-7');
            }
        };

        self::assertTrue(Gate::allows('posts:create', [$resource]));

        $resource->forceFill(['id' => 'model-7']);

        self::assertTrue(Gate::allows('posts:create', [$resource]));
        self::assertSame(['document:contract-7', 'document:contract-7'], $this->evaluatedResources());
        self::assertSame([], $resolver->asked);
    }

    /**
     * A stringable object is identified by its string form.
     *
     * @return void
     */
    public function testStringableObjectIsIdentifiedByItsStringForm(): void
    {
        $this->actAsPrincipalAllowedOn('arn:post:stringable');

        $resource = new class implements \Stringable {
            /**
             * Return the string form of the resource.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'arn:post:stringable';
            }
        };

        self::assertTrue(Gate::allows('posts:create', [$resource]));
        self::assertSame(['arn:post:stringable'], $this->evaluatedResources());
    }

    /**
     * The Gate's user is translated through the subject resolver, and the check
     * decides about the subject the resolver returns, not about the user.
     *
     * @return void
     */
    public function testTheGatesUserIsTranslatedIntoTheSubject(): void
    {
        $principal = $this->actAsFullyPermittedPrincipal();
        $user      = StubIdentity::create(['id' => (string) Str::uuid()]);

        $resolver = \Mockery::mock(SubjectResolver::class);
        $resolver->shouldReceive('forUser')->with($user)->andReturn(new Subject($principal, $user));
        $resolver->shouldReceive('resolve')->andReturnNull();

        $this->app?->instance(SubjectResolver::class, $resolver);
        $this->app?->forgetInstance('authorization');
        Authorization::clearResolvedInstance('authorization');

        self::assertTrue(Gate::forUser($user)->allows('posts:create'));
        self::assertEquals(Reference::of($principal), $this->decisions()[0]->subject);
        self::assertFalse($user->hasPermission('posts:create'));
    }

    /**
     * `Gate::forUser($other)` decides about the other user, not the subject of
     * the request.
     *
     * @return void
     */
    public function testGateForAnotherUserDecidesAboutThatUser(): void
    {
        $this->actAsFullyPermittedPrincipal();

        $other = StubIdentity::create(['id' => (string) Str::uuid()]);

        self::assertTrue(Gate::allows('posts:create'));
        self::assertFalse(Gate::forUser($other)->allows('posts:create'));
        self::assertEquals(Reference::of($other), $this->decisions()[1]->subject);
    }

    /**
     * A guest (no Gate user) is decided as no subject, which denies as
     * `subject_unresolved`, even when the request has a subject the package
     * would allow, and never as that subject.
     *
     * @return void
     */
    public function testAGuestIsDecidedAsNoSubject(): void
    {
        $principal = $this->actAsFullyPermittedPrincipal();

        Gate::define('posts:create', static fn (?object $user = null): bool => true);

        self::assertTrue(Gate::forUser($principal)->allows('posts:create'));
        self::assertFalse(Gate::forUser(null)->allows('posts:create'));
        self::assertNull($this->decisions()[1]->subject);
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $this->decisions()[1]->reason);
        self::assertSame($principal, Authorization::currentSubject()?->subject);
    }

    /**
     * The hook defines no ability: Laravel's Gate holds none of the package's
     * names, yet every case of a configured enum is answered.
     *
     * @return void
     */
    public function testDefinesNoAbilityYetAnswersEveryEnumCase(): void
    {
        $this->actAsFullyPermittedPrincipal();

        self::assertSame([], Gate::abilities());
        self::assertTrue(Gate::allows(PermissionEnum::POSTS_CREATE->value));
        self::assertFalse(Gate::allows(PermissionEnum::POSTS_DELETE->value));
        self::assertSame(['posts:create', 'posts:delete'], $this->evaluatedActions());
    }

    /**
     * The package's allow and its deny both stand over the application's own
     * `Gate::define` callbacks for the same abilities.
     *
     * @return void
     */
    public function testAllowAndDenyStandOverAnApplicationDefine(): void
    {
        $this->actAsFullyPermittedPrincipal();

        Gate::define('posts:create', static fn (?object $user = null): bool => false);
        Gate::define('posts:delete', static fn (?object $user = null): bool => true);

        self::assertTrue(Gate::allows('posts:create'));
        self::assertFalse(Gate::allows('posts:delete'));
        self::assertSame(['posts:create', 'posts:delete'], $this->evaluatedActions());
    }

    /**
     * The package's allow and its deny both stand over a Laravel policy class
     * registered for the resource's model, whatever the policy answers, and a
     * controller's `authorize()` goes through the hook too.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\Access\AuthorizationException
     */
    public function testAllowAndDenyStandOverALaravelPolicyClass(): void
    {
        $target = StubIdentity::create(['id' => 'target-1']);

        $this->actAsPrincipalAllowedOn('stub:target-1');

        Gate::policy(StubIdentity::class, DenyingLaravelPolicy::class);

        self::assertTrue(Gate::allows('posts:create', $target));

        Gate::policy(StubIdentity::class, AllowingLaravelPolicy::class);

        self::assertFalse(Gate::allows('posts:delete', $target));

        $controller = new class {
            use AuthorizesRequests;
        };

        self::assertTrue($controller->authorize('posts:create', $target)->allowed());

        $this->expectException(LaravelAuthorizationException::class);

        $controller->authorize('posts:delete', $target);
    }

    /**
     * An application's `Gate::before` registered after the package's boot runs
     * after the hook, so it never overrides the package's answer.
     *
     * @return void
     */
    public function testAnApplicationBeforeRegisteredAfterThePackageDoesNotOverride(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        Gate::before(static fn (?object $user = null): bool => true);
        Gate::before(static fn (?object $user = null): bool => false);

        // Laravel's `forUser()` copies the before-callbacks in their order.
        self::assertTrue(Gate::forUser($user)->allows('posts:create'));
        self::assertFalse(Gate::forUser($user)->allows('posts:delete'));
        self::assertTrue(Gate::forUser($user)->allows('reports:view'));
    }

    /**
     * An application's `Gate::before` registered before the package boots runs
     * first, and Laravel takes the first answer, so it pre-empts the hook: the
     * documented precedence.
     *
     * @return void
     */
    public function testAnApplicationBeforeRegisteredBeforeThePackagePreEmptsIt(): void
    {
        $this->freshGate();

        Gate::before(static fn (?object $user, string $ability): ?bool => $ability === 'posts:delete' ? true : null);

        (new AuthorizationServiceProvider($this->container()))->boot();

        $this->actAsFullyPermittedPrincipal();

        self::assertTrue(Gate::allows('posts:delete'));
        self::assertTrue(Gate::allows('posts:create'));
        self::assertSame(['posts:create'], $this->evaluatedActions());
    }

    /**
     * An ability the package does not declare falls through to Laravel: a
     * define, a Laravel policy class or nothing decides it, and the package
     * records no decision. The names are matched exactly, so a pattern or a
     * near miss of a declared name is not the package's either.
     *
     * @return void
     */
    public function testUndeclaredAbilitiesFallThroughToLaravel(): void
    {
        $target = StubIdentity::create(['id' => 'target-1']);

        $this->actAsFullyPermittedPrincipal();

        Gate::define('reports:view', static fn (?object $user = null): bool => true);
        Gate::define('posts:*', static fn (?object $user = null): bool => true);
        Gate::define('Posts:Create', static fn (?object $user = null): bool => true);
        Gate::policy(StubIdentity::class, AllowingLaravelPolicy::class);

        self::assertTrue(Gate::allows('reports:view'));
        self::assertTrue(Gate::allows('posts:*'));
        self::assertTrue(Gate::allows('Posts:Create'));
        self::assertTrue(Gate::allows('publish', $target));
        self::assertFalse(Gate::allows('reports:archive'));
        self::assertSame([], $this->decisions());
    }

    /**
     * A permission row that exists only in the database, held by the subject,
     * is not declared, so the Gate leaves it to Laravel, which knows nothing of
     * it, while the package's own API still decides it.
     *
     * @return void
     */
    public function testADatabaseOnlyPermissionFallsThrough(): void
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'reports:archive', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission('reports:archive');

        $this->actAs($user);

        self::assertFalse(Gate::allows('reports:archive'));
        self::assertSame([], $this->decisions());
        self::assertTrue(Authorization::can('reports:archive'));

        Gate::define('reports:archive', static fn (?object $user = null): bool => false);

        self::assertFalse(Gate::allows('reports:archive'));
    }

    /**
     * The permissions a configured provider declares, and the package's own,
     * are answered like an enum's, over the application's define.
     *
     * @return void
     */
    public function testProviderAndPackageAbilitiesAreAnswered(): void
    {
        config(['authorization.permission_providers' => [StubPermissionProvider::class]]);

        foreach (['media:upload', PackagePermissions::GUARDRAIL_MANAGE] as $name) {
            Permission::create(['id' => (string) Str::uuid(), 'name' => $name, 'guard' => 'web']);
            Gate::define($name, static fn (?object $user = null): bool => false);
        }

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission('media:upload');
        $user->givePermission(PackagePermissions::GUARDRAIL_MANAGE);

        $this->actAs($user);

        self::assertTrue(Gate::allows('media:upload'));
        self::assertTrue(Gate::allows(PackagePermissions::GUARDRAIL_MANAGE));
        self::assertFalse(Gate::allows('media:delete'));
        self::assertSame(['media:upload', PackagePermissions::GUARDRAIL_MANAGE, 'media:delete'], $this->evaluatedActions());
    }

    /**
     * `@can` and the `can:` route middleware ask the Gate, so the package
     * decides them, over the application's define.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\Access\AuthorizationException
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function testBladeAndTheCanMiddlewareGoThroughTheHook(): void
    {
        $this->actAsFullyPermittedPrincipal();

        Gate::define('posts:create', static fn (?object $user = null): bool => false);
        Gate::define('posts:delete', static fn (?object $user = null): bool => true);

        self::assertSame('allowed', \trim(Blade::render('@can(\'posts:create\') allowed @else refused @endcan')));
        self::assertSame('refused', \trim(Blade::render('@can(\'posts:delete\') allowed @else refused @endcan')));

        /** @var \Illuminate\Auth\Middleware\Authorize $middleware */
        $middleware = $this->app?->make(Authorize::class);
        $next       = static fn (): Response => new Response('ok');

        /** @var \Illuminate\Http\Response $response */
        $response = $middleware->handle(Request::create('/posts'), $next, 'posts:create');

        self::assertSame('ok', $response->getContent());

        $this->expectException(LaravelAuthorizationException::class);

        $middleware->handle(Request::create('/posts'), $next, 'posts:delete');
    }

    /**
     * With `authorization.gate.enabled` false, booting registers no hook and
     * defines nothing, so Laravel decides even the package's own abilities.
     *
     * @return void
     */
    public function testTheSwitchOffRegistersNothing(): void
    {
        $this->freshGate();

        config(['authorization.gate.enabled' => false]);
        $this->app?->forgetInstance(DeclaredAbilities::class);
        $this->app?->offsetUnset(DeclaredAbilities::class);

        (new AuthorizationServiceProvider($this->container()))->boot();

        $this->actAsFullyPermittedPrincipal();

        self::assertFalse($this->app?->bound(DeclaredAbilities::class));
        self::assertSame([], Gate::abilities());
        self::assertFalse(Gate::allows('posts:create'));

        Gate::define('posts:delete', static fn (?object $user = null): bool => true);

        self::assertTrue(Gate::forUser(new \stdClass)->allows('posts:delete'));
        self::assertSame([], $this->decisions());
    }

    /**
     * The switch is on unless it is false: the hook is enabled when
     * `authorization.gate.enabled` is true or absent, and only false turns it
     * off.
     *
     * @return void
     */
    public function testTheSwitchIsOnUnlessItIsFalse(): void
    {
        $config = config();

        $config->set('authorization.gate', ['enabled' => true]);
        self::assertTrue(GateRegistrar::isEnabled($config));

        $config->set('authorization.gate', ['enabled' => false]);
        self::assertFalse(GateRegistrar::isEnabled($config));

        $config->set('authorization.gate', []);
        self::assertTrue(GateRegistrar::isEnabled($config));
    }

    /**
     * A `gate` block without the switch keeps the hook on: registering on a
     * fresh Gate answers a declared ability through the package, over a define
     * that would refuse it.
     *
     * @return void
     */
    public function testAGateBlockWithoutTheSwitchRegistersTheHook(): void
    {
        $this->freshGate();

        config(['authorization.gate' => []]);
        $this->app?->forgetInstance(DeclaredAbilities::class);
        $this->app?->offsetUnset(DeclaredAbilities::class);

        (new GateRegistrar($this->container()))->register();

        $this->actAsFullyPermittedPrincipal();

        Gate::define('posts:create', static fn (?object $user = null): bool => false);

        self::assertTrue($this->app?->bound(DeclaredAbilities::class));
        self::assertTrue(Gate::allows('posts:create'));
        self::assertSame(['posts:create'], $this->evaluatedActions());
    }

    /**
     * With the shipped resolver, the user Laravel signed in is the Gate's user
     * and the subject of the check.
     *
     * @return void
     */
    public function testTheSignedInUserIsTheGatesSubject(): void
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard' => 'web']);

        $user = AuthenticatableIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission('posts:create');

        self::assertFalse(Gate::allows('posts:create'));

        $this->actingAs($user);

        self::assertTrue(Gate::allows('posts:create'));
        self::assertEquals(Reference::of($user), $this->decisions()[1]->subject);
    }

    /**
     * Assert the Gate refuses the supplied leading argument with exactly one
     * recorded unresolved-resource refusal for the supplied principal.
     *
     * @param  mixed  $argument
     * @param  \Tests\Feature\Stubs\StubIdentity  $principal
     * @return void
     */
    private function assertGateRefusesUnidentifiedArgument(mixed $argument, StubIdentity $principal): void
    {
        $previousCount = \count($this->decisions());

        self::assertFalse(Gate::allows('posts:create', [$argument]));

        $this->assertRefusalRecorded($previousCount, $principal);
    }

    /**
     * Assert exactly one decision was dispatched after the supplied number of
     * earlier decisions, and that it is a refusal at the resource stage for a
     * check about no resource that consulted no policy or RBAC grant.
     *
     * A principal with a wildcard-resource allow and the RBAC permission would
     * be allowed by either, so the unresolved-resource reason and the empty
     * trace prove neither was evaluated.
     *
     * @param  int  $previousCount
     * @param  \Tests\Feature\Stubs\StubIdentity  $principal
     * @param  array<string, mixed>  $context
     * @return void
     *
     * @throws \JsonException
     */
    private function assertRefusalRecorded(int $previousCount, StubIdentity $principal, array $context = []): void
    {
        $decisions = $this->decisions();

        self::assertCount($previousCount + 1, $decisions);

        $decision = $decisions[$previousCount];

        self::assertEquals(Reference::of($principal), $decision->subject);
        self::assertSame('posts:create', $decision->action);
        self::assertNull($decision->resource);
        self::assertSame([], $decision->keys);
        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, $decision->reason);
        self::assertSame([], $decision->statements);
        self::assertSame(DecisionStage::RESOURCE, Authorization::lastDecision()?->stage);
        self::assertSame([], Authorization::lastDecision()->trace);

        foreach ($context as $value) {
            self::assertStringNotContainsString(\json_encode($value, \JSON_THROW_ON_ERROR), \serialize($decision));
        }
    }

    /**
     * Assert the same principal is allowed a resource-less check, so a denial
     * recorded earlier in the test is down to the argument alone.
     *
     * @return void
     */
    private function assertResourcelessCheckStillAllowed(): void
    {
        $previousCount = \count($this->decisions());

        self::assertTrue(Gate::allows('posts:create', [null]));

        $decisions = $this->decisions();

        self::assertCount($previousCount + 1, $decisions);
        self::assertNull($decisions[$previousCount]->resource);
        self::assertEquals([$this->wildcardAllowReference()], $decisions[$previousCount]->statements);
        self::assertEquals($decisions[$previousCount]->statements, Authorization::lastDecision()?->statements);
    }

    /**
     * Return every decision event dispatched so far, in order.
     *
     * @return list<\SineMacula\Laravel\Authorization\Events\DecisionEvaluated>
     */
    private function decisions(): array
    {
        return self::dispatchedEvents(DecisionEvaluated::class);
    }

    /**
     * Return the action of every decision evaluated so far, in order.
     *
     * @return list<string>
     */
    private function evaluatedActions(): array
    {
        return \array_map(static fn (DecisionEvaluated $decision): string => $decision->action, $this->decisions());
    }

    /**
     * Replace Laravel's Gate with a new one holding no callback, as before any
     * provider booted, so a test can register before the package does.
     *
     * @return void
     */
    private function freshGate(): void
    {
        $this->app?->forgetInstance(GateContract::class);

        Gate::clearResolvedInstance(GateContract::class);
    }

    /**
     * Return the resource of every decision evaluated so far, in order.
     *
     * @return list<string|null>
     */
    private function evaluatedResources(): array
    {
        return \array_map(static fn (DecisionEvaluated $decision): ?string => $decision->resource, $this->decisions());
    }

    /**
     * Act as a principal that both holds the permission and carries a
     * wildcard-resource allow, so any check that is evaluated is allowed.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function actAsFullyPermittedPrincipal(): StubIdentity
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission('posts:create');

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'wildcard-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create']],
                ],
            ],
        ]));

        $this->actAs($user);

        return $user;
    }

    /**
     * Return the reference to the stored wildcard-resource allow policy's only
     * statement, carrying the policy's key.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\StatementReference
     */
    private function wildcardAllowReference(): StatementReference
    {
        $policy = Policy::query()->where('name', 'wildcard-allow')->sole();

        return new StatementReference('wildcard-allow', 0, $policy->id);
    }

    /**
     * Act as a principal allowed the action on the supplied resource only.
     *
     * @param  string  $resource
     * @return void
     */
    private function actAsPrincipalAllowedOn(string $resource): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'scoped-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => [$resource]],
                ],
            ],
        ]));

        $this->actAs($user);
    }

    /**
     * Swap the subject resolver for one that returns the supplied authorizable
     * and refresh the manager so the next facade call picks it up.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return void
     */
    private function actAs(StubIdentity $user): void
    {
        $resolver = new StubSubjectResolver($user);

        $this->container()->instance(SubjectResolver::class, $resolver);
        $this->container()->forgetInstance('authorization');
        $this->container()->forgetInstance(AuthorizationManager::class);

        // The Gate decides about the user it hands over, as a signed-in user's
        // would be, since a guest is decided as no subject.
        Gate::swap(Gate::forUser($user));
    }
}
