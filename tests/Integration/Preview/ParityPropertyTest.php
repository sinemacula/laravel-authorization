<?php

declare(strict_types = 1);

namespace Tests\Integration\Preview;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Preview\PreviewContext;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\PreviewsSubjects;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\TestCase;

/**
 * The preview parity property over one seeded scenario: with tenants, a role
 * hierarchy, resource policies and a boundary combined, and the previewer
 * holding an action the target lacks in tenants only it anchors, a preview
 * decides every check, batch and scoped query as `for()` does under the same
 * scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PreviewContext::class)]
final class ParityPropertyTest extends TestCase
{
    use PreviewsSubjects;

    /** @var list<string> The actions every post is checked for. */
    private const array ACTIONS = ['posts:view', 'posts:edit', 'posts:publish', 'posts:delete'];

    /**
     * A preview answers every check, batch and scoped query as `for()` does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviewDecidesAsForDoesAcrossTenantsRolesPoliciesAndBoundaries(): void
    {
        [$manager, $target, $posts] = $this->scenario();

        $preview = $manager->previewFor($target);
        $named   = $manager->for($target);
        $checks  = [];

        foreach ($posts as $title => $post) {
            foreach (self::ACTIONS as $action) {
                $checks["{$title} {$action}"] = new CheckInput($action, $post);

                self::assertSame(self::outcome($named->check($action, $post)), self::outcome($preview->check($action, $post)), "{$title} {$action}");
            }
        }

        self::assertSame(\array_map(self::outcome(...), $named->checkMany($checks)), \array_map(self::outcome(...), $preview->checkMany($checks)));

        foreach (self::ACTIONS as $action) {
            self::assertSame(self::titles($named, $action), self::titles($preview, $action), $action);
        }

        self::assertSame(['child', 'parent', 'shared', 'team'], self::titles($preview, 'posts:view'));
        self::assertSame(['child', 'parent', 'team'], self::titles($preview, 'posts:edit'));
        self::assertSame([], self::titles($preview, 'posts:publish'));
        self::assertSame([], self::titles($preview, 'posts:delete'));
    }

    /**
     * Seed the scenario and return the caller's manager, signed in at the
     * parent tenant, the target and its posts by title.
     *
     * @return array{\SineMacula\Laravel\Authorization\AuthorizationManager, \Tests\Feature\Stubs\StubGrantee, array<string, \Tests\Fixtures\QueryScoping\TenantScopedPost>}
     *
     * @throws \Throwable
     */
    private function scenario(): array
    {
        $tenant                            = static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]);
        [$parent, $child, $team, $sibling] = \array_map($tenant, ['parent', 'child', 'team', 'sibling']);

        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        ClosureTenantTree::add(Reference::of($parent));
        ClosureTenantTree::add(Reference::of($child), Reference::of($parent));
        ClosureTenantTree::add(Reference::of($team), Reference::of($parent));
        ClosureTenantTree::add(Reference::of($sibling));

        $caller = self::previewer();
        $target = self::target('target', ['posts:view']);
        $grants = GrantService::instance();
        $roles  = RoleService::instance();

        self::assertInstanceOf(GrantService::class, $grants);
        self::assertInstanceOf(RoleService::class, $roles);

        $grants->grantPermission($caller, self::permission('posts:publish'), tenant: $team);
        $grants->grantPermission($caller, self::permission('posts:publish'), tenant: $sibling);

        $viewer = Role::query()->create(['name' => 'viewer']);
        $editor = Role::query()->create(['name' => 'editor']);

        $roles->grantPermission($viewer, self::permission('posts:edit'));
        $roles->grantPermission($editor, self::permission('posts:delete'));
        $roles->setParent($editor, $viewer);
        $grants->grantRole($target, $editor, tenant: $parent);

        BoundaryService::instance()?->set($target, self::policy('no-deletes', [['effect' => 'allow', 'actions' => ['posts:view', 'posts:edit', 'posts:publish']]]));

        $posts = [];

        foreach (['parent' => $parent, 'child' => $child, 'hidden' => $child, 'team' => $team, 'shared' => $sibling, 'other' => $sibling] as $title => $tenant) {
            $posts[$title] = TenantScopedPost::query()->create(['title' => $title, 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => $tenant->getKey()]);
        }

        self::attach(self::policy('hidden', [['effect' => 'deny', 'actions' => ['posts:view', 'posts:edit']]]), $posts['hidden'], $child);
        self::attach(self::policy('other', [['effect' => 'deny', 'actions' => ['posts:view']]]), $posts['other'], $sibling);

        return [$this->signIn($caller, 'session-1', $parent), $target, $posts];
    }

    /**
     * Return the titles of the posts the manager's scoped query keeps for the
     * action, sorted.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  string  $action
     * @return list<string>
     */
    private static function titles(AuthorizationManager $manager, string $action): array
    {
        /** @var \Illuminate\Database\Eloquent\Builder<\Tests\Fixtures\QueryScoping\TenantScopedPost> $query */
        $query = TenantScopedPost::query()->whereAuthorized($action, [], $manager); // @phpstan-ignore method.notFound

        /** @var list<string> */
        return $query->orderBy('title')->pluck('title')->all();
    }

    /**
     * Return whether the decision allows and its reason, none for an allow.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return array{bool, string|null}
     */
    private static function outcome(Decision $decision): array
    {
        return [$decision->isAllowed(), $decision->reason?->value];
    }

    /**
     * Return a stored policy of the statements.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, array $statements): Policy
    {
        return Policy::query()->create(['name' => $name, 'document' => ['statements' => $statements]]);
    }

    /**
     * Attach the policy to the post in its tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \Tests\Fixtures\QueryScoping\TenantScopedPost  $post
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return void
     *
     * @throws \Throwable
     */
    private static function attach(Policy $policy, TenantScopedPost $post, StubTenant $tenant): void
    {
        ResourcePolicyService::instance()?->attach($policy, $post, $tenant);
    }
}
