<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\FoundationUser;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * The README's journey, on the shipped bindings and a user model extending
 * Laravel's own. The routes bind `{post}` to a `StubTenant`, named `post` in
 * the morph map.
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
final class ApiJourneyTest extends TestCase
{
    /** @var array<string, class-string<\Illuminate\Database\Eloquent\Model>> The morph map before the test. */
    private array $morphMap = [];

    /**
     * Restore the shipped catalogues, then register the morph map and routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container()->forgetExtenders(ActionCatalogue::class);
        $this->container()->forgetExtenders(ContextKeyCatalogue::class);
        $this->container()->forgetInstance(ContextKeyCatalogue::class);
        $this->container()->forgetScopedInstances();

        $this->morphMap = Relation::morphMap();

        Relation::morphMap(['post' => StubTenant::class]);

        Route::middleware('permission:posts:create')->get('/posts', static fn (): string => 'ok');

        Route::middleware([SubstituteBindings::class, 'authorize:posts:create,post'])
            ->get('/posts/{post}', static fn (StubTenant $post): string => 'ok');

        Route::middleware([SubstituteBindings::class, 'can:posts:create,post'])
            ->get('/posts/{post}/edit', static fn (StubTenant $post): string => 'ok');

        Route::middleware([SubstituteBindings::class, 'authorize:posts:delete,post'])
            ->delete('/posts/{post}', static fn (StubTenant $post): string => 'ok');
    }

    /**
     * Restore the morph map.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap($this->morphMap, false);

        parent::tearDown();
    }

    /**
     * A role granted from the synced catalogue passes every surface, which each
     * decide on the model they are given.
     *
     * @return void
     */
    public function testARoleFromTheSyncedCataloguePassesEverySurface(): void
    {
        self::assertInstanceOf(DeclaredActionCatalogue::class, $this->container()->make(ActionCatalogue::class));
        self::assertInstanceOf(DeclaredContextKeyCatalogue::class, $this->container()->make(ContextKeyCatalogue::class));

        $user     = $this->editor();
        $post     = StubTenant::create(['id' => 'post-42']);
        $archived = StubTenant::create(['id' => 'post-7']);

        $user->attachPolicy(Policy::create([
            'name'     => 'no-archived-posts',
            'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:create'], 'resources' => ['post:post-7']]]],
        ]));

        self::assertTrue($user->can('posts:create'));
        self::assertTrue($user->can('posts:create', $post));
        self::assertTrue($user->cannot('posts:create', $archived));
        self::assertTrue($user->cannot('posts:delete', $post));
        self::assertTrue(Gate::forUser($user)->allows('posts:create', $post));
        self::assertTrue(Gate::forUser($user)->denies('posts:create', $archived));

        $this->actingAs($user);

        $this->getJson('/posts')->assertOk();
        $this->getJson('/posts/post-42')->assertOk();
        $this->getJson('/posts/post-7')->assertForbidden();
        $this->getJson('/posts/post-42/edit')->assertOk();
        $this->getJson('/posts/post-7/edit')->assertForbidden();
    }

    /**
     * The README's network deny and a revoked role each refuse the next
     * request.
     *
     * @return void
     */
    public function testTheNetworkDenyAndARevocationRefuseTheNextRequest(): void
    {
        $user = $this->editor();
        $post = StubTenant::create(['id' => 'post-42']);

        $user->givePermission('posts:delete', now()->addDay());

        $this->actingAs($user);

        $this->deleteJson('/posts/post-42')->assertOk();

        $user->attachPolicy(Policy::create([
            'name'     => 'no-deletes-off-network',
            'document' => [
                'statements' => [
                    [
                        'effect'     => 'deny',
                        'actions'    => ['posts:delete'],
                        'conditions' => ['ip_not_in' => ['request.ip' => ['10.0.0.0/8', '192.168.0.0/16']]],
                    ],
                ],
            ],
        ]));

        self::assertFalse(Authorization::for($user)->can('posts:delete', 'posts/42'));
        self::assertTrue($user->cannot('posts:delete', $post));

        $this->deleteJson('/posts/post-42')->assertForbidden();
        $this->withServerVariables(['REMOTE_ADDR' => '10.1.2.3'])->deleteJson('/posts/post-42')->assertOk();

        $this->getJson('/posts')->assertOk();

        $user->revokeRole('editor');

        $this->getJson('/posts')->assertForbidden();
        $this->getJson('/posts/post-42')->assertForbidden();
        $this->getJson('/posts/post-42/edit')->assertForbidden();
        self::assertTrue($user->cannot('posts:create', $post));
    }

    /**
     * Declare the permission enum before the package boots.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('authorization.permission_enums', [PermissionEnum::class]);
    }

    /**
     * Sync the catalogue and return a user holding the README's editor role.
     *
     * @return \Tests\Feature\Stubs\FoundationUser
     */
    private function editor(): FoundationUser
    {
        self::assertSame(0, Artisan::call('authorization:sync'));
        self::assertTrue(Permission::query()->where('name', 'posts:create')->exists());

        Role::create(['name' => 'editor'])->givePermission('posts:create');

        $user = FoundationUser::create(['name' => 'Ada']);
        $user->assignRole('editor');

        return $user;
    }
}
