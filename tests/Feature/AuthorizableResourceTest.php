<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
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
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;
use SineMacula\Laravel\Authorization\Support\ResourceScope;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the `AuthorizableResource` contract integration with the
 * Gate translation layer and the tenant a resource names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(AuthorizationManager::class)]
#[CoversClass(ResourceReferences::class)]
#[CoversClass(ResourceScope::class)]
final class AuthorizableResourceTest extends TestCase
{
    /**
     * Boot the provider with the demo permission enum so the Gate is wired for
     * each test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        (new AuthorizationServiceProvider($this->app))->boot();
    }

    /**
     * An object implementing `AuthorizableResource` is converted via
     * `toResourceReference()` when passed through the Gate.
     *
     * @return void
     */
    public function testAuthorizableResourceIsUsedByGate(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'custom-resource',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['custom:resource:42']],
                ],
            ],
        ]));

        $resource = new class implements AuthorizableResource {
            /**
             * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
             */
            #[\Override]
            public function toResourceReference(): ResourceReference
            {
                return new ResourceReference('custom:resource:42');
            }
        };

        self::assertTrue(Gate::allows('posts:create', $resource));
    }

    /**
     * `AuthorizableResource` takes precedence over `__toString` and Eloquent
     * model stringification.
     *
     * @return void
     */
    public function testAuthorizableResourceTakesPrecedenceOverToString(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'precedence-check',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['authorizable:id']],
                ],
            ],
        ]));

        // Object implements both AuthorizableResource and __toString — the
        // contract method should win.
        $resource = new class implements AuthorizableResource {
            /**
             * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
             */
            #[\Override]
            public function toResourceReference(): ResourceReference
            {
                return new ResourceReference('authorizable:id');
            }

            /**
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'tostring:id';
            }
        };

        self::assertTrue(Gate::allows('posts:create', $resource));
    }

    /**
     * A non-matching `AuthorizableResource` identifier correctly denies access.
     *
     * @return void
     */
    public function testNonMatchingAuthorizableResourceIsDenied(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'deny-mismatch',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['custom:resource:99']],
                ],
            ],
        ]));

        $resource = new class implements AuthorizableResource {
            /**
             * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
             */
            #[\Override]
            public function toResourceReference(): ResourceReference
            {
                return new ResourceReference('custom:resource:1');
            }
        };

        self::assertFalse(Gate::allows('posts:create', $resource));
    }

    /**
     * The contract wins over a model's own record and the tenant the bound
     * resolver reads for it, so a model naming no tenant is decided where the
     * request is; the model is still handed on with the record it names.
     *
     * @return void
     */
    public function testAuthorizableResourceWinsOverTheModelAndItsResolver(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);
        $this->bindResourceTenant(new Reference(StubTenant::class, 'tenant-b'));
        $this->allowEveryResource($user, 'model-precedence');

        $resource = new class extends Model implements AuthorizableResource {
            /** @var bool The key is set by hand. */
            public $incrementing = false;

            /**
             * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
             */
            #[\Override]
            public function toResourceReference(): ResourceReference
            {
                return ResourceReference::record('document', '7');
            }
        };

        $resource->setRawAttributes(['id' => '42']);

        self::assertEquals(ResourceReference::record('document', '7', null, $resource), ResourceReferences::of($resource));
        self::assertTrue(Gate::allows('posts:create', $resource));
        self::assertTrue(Authorization::for($user)->check('posts:create', $resource)->isAllowed());
        self::assertSame(DecisionReason::TENANT_SCOPE, Authorization::for($user)->check('posts:create', $user)->reason);
    }

    /**
     * A tenant the contract names is kept: with no tenant active, its resource
     * is out of scope and denied before any policy is read.
     *
     * @return void
     */
    public function testTheContractsTenantIsKept(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);
        $this->allowEveryResource($user, 'out-of-scope');

        $resource = self::resourceIn(new Reference(StubTenant::class, 'tenant-b'));
        $decision = Authorization::for($user)->check('posts:create', $resource);

        self::assertFalse(Gate::allows('posts:create', $resource));
        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::TENANT_SCOPE, $decision->reason);
        self::assertSame(DecisionStage::TENANT, $decision->stage);
    }

    /**
     * A resource the contract places in the active tenant is decided in that
     * tenant, and one in another tenant is out of scope.
     *
     * @return void
     */
    public function testTheContractsTenantIsDecidedInTheActiveTenant(): void
    {
        $tenant = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $user   = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user, $tenant);
        $this->allowEveryResource($user, 'in-scope');

        self::assertTrue(Gate::allows('posts:create', self::resourceIn(new Reference($tenant->getMorphClass(), 'tenant-a'))));
        self::assertFalse(Gate::allows('posts:create', self::resourceIn(new Reference($tenant->getMorphClass(), 'tenant-b'))));
    }

    /**
     * Swap the subject resolver for the supplied identity, in the given tenant
     * or none.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  object|null  $tenant
     * @return void
     */
    private function actAs(StubIdentity $user, ?object $tenant = null): void
    {
        $resolver = new StubSubjectResolver($user, $tenant);

        $this->app->instance(SubjectResolver::class, $resolver); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance('authorization'); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance(AuthorizationManager::class); // @phpstan-ignore method.nonObject
    }

    /**
     * Bind a resource tenant resolver that places every model in the given
     * tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return void
     */
    private function bindResourceTenant(Reference $tenant): void
    {
        $this->app?->instance(ResourceTenantResolver::class, new readonly class ($tenant) implements ResourceTenantResolver {
            /**
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
             */
            public function __construct(

                /** The tenant the resource belongs to. */
                private Reference $tenant,
            ) {}

            /**
             * @param  \Illuminate\Database\Eloquent\Model  $resource
             * @return \SineMacula\Laravel\Authorization\Support\Reference
             */
            #[\Override]
            public function tenantOf(Model $resource): Reference
            {
                return $this->tenant;
            }

            /**
             * @param  string  $type
             * @param  string  $id
             * @return \SineMacula\Laravel\Authorization\Support\Reference
             */
            #[\Override]
            public function tenantOfRecord(string $type, string $id): Reference
            {
                return $this->tenant;
            }
        });
    }

    /**
     * Attach a platform-wide policy allowing `posts:create` on every resource.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  string  $name
     * @return void
     */
    private function allowEveryResource(StubIdentity $user, string $name): void
    {
        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => $name,
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['*']],
                ],
            ],
        ]));
    }

    /**
     * Build a resource the contract places in the given tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \SineMacula\Laravel\Authorization\Contracts\AuthorizableResource
     */
    private static function resourceIn(Reference $tenant): AuthorizableResource
    {
        return new readonly class ($tenant) implements AuthorizableResource {
            /**
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
             */
            public function __construct(

                /** The tenant the resource belongs to. */
                private Reference $tenant,
            ) {}

            /**
             * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
             */
            #[\Override]
            public function toResourceReference(): ResourceReference
            {
                return ResourceReference::record('document', '7', $this->tenant);
            }
        };
    }
}
