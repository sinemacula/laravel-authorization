<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions as Actions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\CatchesRefusals;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for delegated administration (AUTHZ-11.1) through every
 * management service: each change a call names an acting context for is decided
 * through `check()` under its administration action, before anything is
 * written, and refused, leaving nothing written and dispatching no change
 * event, when it is not allowed or, widening authority, cannot be proved
 * permitted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 *
 * @phpstan-type Setup \Closure(): (\Closure(\SineMacula\Laravel\Authorization\Administration\ActingContext): mixed)
 */
#[CoversClass(GrantService::class)]
#[CoversClass(RoleService::class)]
#[CoversClass(PermissionService::class)]
#[CoversClass(PolicyService::class)]
#[CoversClass(BoundaryService::class)]
#[CoversClass(ResourcePolicyService::class)]
final class DelegatedAdministrationTest extends TestCase
{
    use ActsAsAdministrator, CatchesRefusals;

    /** @var list<string> The tables a management service writes. */
    private const array TABLES = [
        'roles', 'permissions', 'policies', 'role_permissions', 'authorizable_roles', 'authorizable_permissions', 'authorizable_policies',
        'authorizable_boundaries', 'resource_policies', 'guardrails',
    ];

    /**
     * Fake the package's events, and those alone, before anything resolves the
     * dispatcher, so the models' own events still run their observers.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Event::fake([static fn (string $name): bool => \is_subclass_of($name, AuthorizationEvent::class)]);

        // Every record a call names exists before it is made, so a refused call
        // is seen to write nothing.
        self::user();

        foreach (['editor', 'author', 'staff'] as $role) {
            self::role($role);
        }

        foreach (['posts:edit', 'posts:read'] as $permission) {
            self::permission($permission);
        }

        foreach (['reader' => 'allow', 'denying' => 'deny', 'cap' => 'allow'] as $policy => $effect) {
            self::policy($policy, $effect);
        }

        self::sharing('allow');
        self::sharing('deny');
    }

    /**
     * Every mutating method of every management service, as `calls()` gives it,
     * with the actions it decides alone.
     *
     * @return iterable<string, array{Setup, list<string>}>
     */
    public static function actions(): iterable
    {
        foreach (self::calls() as $name => [$setup, $actions]) {
            yield $name => [$setup, $actions];
        }
    }

    /**
     * Called with an actor that holds no administration action, every call is
     * refused at its first change, as the decision refuses it, before anything
     * is written, dispatching no change event.
     *
     * @param  Setup  $setup
     * @param  list<string>  $actions
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('actions')]
    public function testEveryCallIsRefusedWithoutItsAction(\Closure $setup, array $actions): void
    {
        $actor = self::administrator([]);
        $call  = $setup();

        self::assertRefusedWithNothingWritten($call, $actor, DecisionReason::NO_MATCH, $actions[0]);
    }

    /**
     * Called with an actor denied the call's first action alone, every call is
     * refused as that deny refuses it: each decides its own action.
     *
     * @param  Setup  $setup
     * @param  list<string>  $actions
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('actions')]
    public function testEveryCallDecidesItsOwnAction(\Closure $setup, array $actions): void
    {
        $actor = self::administrator();
        $call  = $setup();

        $deny = Policy::create(['name' => 'no-' . $actions[0], 'document' => ['statements' => [['effect' => 'deny', 'actions' => [$actions[0]]]]]]);

        self::grants()->attachPolicy(StubIdentity::query()->findOrFail('admin-1'), $deny);

        self::assertRefusedWithNothingWritten($call, $actor, DecisionReason::EXPLICIT_DENY, $actions[0]);
    }

    /**
     * Every mutating method of every management service, as a setup that
     * returns the call to make with an acting context, the administration
     * actions the call decides, in order, and what it is refused with once the
     * actor holds every action, null for a change that is made.
     *
     * @return iterable<string, array{Setup, list<string>, \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null}>
     */
    public static function calls(): iterable
    {
        $unprovable = DecisionReason::ADMINISTRATION_UNPROVABLE;

        yield 'grantRole' => [
            self::directly(static fn (ActingContext $actor): mixed => self::grants()->grantRole(self::user(), self::role('editor'), actor: $actor)),
            [Actions::ROLE_GRANT],
            null,
        ];
        yield 'revokeRole' => [static function (): \Closure {
            self::grants()->grantRole(self::user(), self::role('editor'));

            return static fn (ActingContext $actor): mixed => self::grants()->revokeRole(self::user(), 'editor', $actor);
        }, [Actions::ROLE_REVOKE], null];
        yield 'revokeRole of a role a deny is attached to' => [static function (): \Closure {
            self::grants()->grantRole(self::user(), self::role('editor'));
            self::grants()->attachPolicy(self::role('editor'), self::policy('denying', 'deny'));

            return static fn (ActingContext $actor): mixed => self::grants()->revokeRole(self::user(), 'editor', $actor);
        }, [Actions::ROLE_REVOKE], $unprovable];
        yield 'syncRoles granting' => [
            self::directly(static fn (ActingContext $actor): mixed => self::grants()->syncRoles(self::user(), [self::role('editor')], actor: $actor)),
            [Actions::ROLE_GRANT],
            null,
        ];
        yield 'syncRoles revoking' => [static function (): \Closure {
            self::grants()->grantRole(self::user(), self::role('editor'));

            return static fn (ActingContext $actor): mixed => self::grants()->syncRoles(self::user(), [], actor: $actor);
        }, [Actions::ROLE_REVOKE], null];
        yield 'grantPermission' => [
            self::directly(static fn (ActingContext $actor): mixed => self::grants()->grantPermission(self::user(), self::permission('posts:edit'), actor: $actor)),
            [Actions::PERMISSION_GRANT],
            null,
        ];
        yield 'revokePermission' => [static function (): \Closure {
            self::grants()->grantPermission(self::user(), self::permission('posts:edit'));

            return static fn (ActingContext $actor): mixed => self::grants()->revokePermission(self::user(), self::permission('posts:edit'), $actor);
        }, [Actions::PERMISSION_REVOKE], null];
        yield 'syncPermissions' => [static function (): \Closure {
            self::grants()->grantPermission(self::user(), self::permission('posts:edit'));

            return static fn (ActingContext $actor): mixed => self::grants()->syncPermissions(self::user(), [self::permission('posts:read')], actor: $actor);
        }, [Actions::PERMISSION_GRANT, Actions::PERMISSION_REVOKE], null];
        yield 'attachPolicy' => [
            self::directly(static fn (ActingContext $actor): mixed => self::grants()->attachPolicy(self::user(), self::policy('reader', 'allow'), actor: $actor)),
            [Actions::POLICY_ATTACH],
            null,
        ];
        yield 'detachPolicy of an allow-only policy' => [static function (): \Closure {
            self::grants()->attachPolicy(self::user(), self::policy('reader', 'allow'));

            return static fn (ActingContext $actor): mixed => self::grants()->detachPolicy(self::user(), self::policy('reader', 'allow'), $actor);
        }, [Actions::POLICY_DETACH], null];
        yield 'detachPolicy of a denying policy' => [static function (): \Closure {
            self::grants()->attachPolicy(self::user(), self::policy('denying', 'deny'));

            return static fn (ActingContext $actor): mixed => self::grants()->detachPolicy(self::user(), self::policy('denying', 'deny'), $actor);
        }, [Actions::POLICY_DETACH], $unprovable];
        yield 'syncPolicies revoking' => [static function (): \Closure {
            self::grants()->attachPolicy(self::user(), self::policy('reader', 'allow'));

            return static fn (ActingContext $actor): mixed => self::grants()->syncPolicies(self::user(), [], actor: $actor);
        }, [Actions::POLICY_DETACH], null];
        yield 'revokeAll' => [static function (): \Closure {
            self::grants()->grantRole(self::user(), self::role('editor'));
            self::grants()->grantPermission(self::user(), self::permission('posts:edit'));

            return static fn (ActingContext $actor): mixed => self::grants()->revokeAll(self::user(), $actor);
        }, [Actions::ROLE_REVOKE, Actions::PERMISSION_REVOKE], null];
        yield 'revokeAll removing a boundary' => [static function (): \Closure {
            self::grants()->grantPermission(self::user(), self::permission('posts:edit'));
            self::boundaries()->set(self::user(), self::policy('cap', 'allow'));

            return static fn (ActingContext $actor): mixed => self::grants()->revokeAll(self::user(), $actor);
        }, [Actions::PERMISSION_REVOKE, Actions::BOUNDARY_REMOVE], null];
        yield 'RoleService::create' => [
            self::directly(static fn (ActingContext $actor): mixed => self::roles()->create('newcomer', actor: $actor)),
            [Actions::ROLE_CREATE],
            null,
        ];
        yield 'RoleService::rename' => [
            self::directly(static fn (ActingContext $actor): mixed => self::roles()->rename(self::role('editor'), 'writer', $actor)),
            [Actions::ROLE_RENAME],
            null,
        ];
        yield 'RoleService::describe' => [
            self::directly(static fn (ActingContext $actor): mixed => self::roles()->describe(self::role('editor'), 'Edits', $actor)),
            [Actions::ROLE_UPDATE],
            null,
        ];
        yield 'RoleService::delete' => [self::directly(static function (ActingContext $actor): mixed {
            self::roles()->delete(self::role('editor'), $actor);

            return null;
        }), [Actions::ROLE_DELETE], null];
        yield 'RoleService::setParent' => [
            self::directly(static fn (ActingContext $actor): mixed => self::roles()->setParent(self::role('editor'), self::role('staff'), $actor)),
            [Actions::ROLE_PARENT_SET],
            null,
        ];
        yield 'RoleService::grantPermission' => [
            self::directly(static fn (ActingContext $actor): mixed => self::roles()->grantPermission(self::role('editor'), self::permission('posts:edit'), actor: $actor)),
            [Actions::PERMISSION_GRANT],
            null,
        ];
        yield 'RoleService::revokePermission' => [static function (): \Closure {
            self::roles()->grantPermission(self::role('editor'), self::permission('posts:edit'));

            return static fn (ActingContext $actor): mixed => self::roles()->revokePermission(self::role('editor'), 'posts:edit', $actor);
        }, [Actions::PERMISSION_REVOKE], null];
        yield 'RoleService::syncPermissions granting' => [
            self::directly(static fn (ActingContext $actor): mixed => self::roles()->syncPermissions(self::role('editor'), [self::permission('posts:edit')], actor: $actor)),
            [Actions::PERMISSION_GRANT],
            null,
        ];
        yield 'RoleService::syncPermissions revoking' => [static function (): \Closure {
            self::roles()->grantPermission(self::role('editor'), self::permission('posts:edit'));

            return static fn (ActingContext $actor): mixed => self::roles()->syncPermissions(self::role('editor'), [], actor: $actor);
        }, [Actions::PERMISSION_REVOKE], null];
        yield 'PermissionService::create' => [
            self::directly(static fn (ActingContext $actor): mixed => self::permissions()->create('posts:new', actor: $actor)),
            [Actions::PERMISSION_CREATE],
            null,
        ];
        yield 'PermissionService::rename' => [
            self::directly(static fn (ActingContext $actor): mixed => self::permissions()->rename(self::permission('posts:edit'), 'posts:write', $actor)),
            [Actions::PERMISSION_RENAME],
            null,
        ];
        yield 'PermissionService::describe' => [
            self::directly(static fn (ActingContext $actor): mixed => self::permissions()->describe(self::permission('posts:edit'), 'Edit', $actor)),
            [Actions::PERMISSION_UPDATE],
            null,
        ];
        yield 'PermissionService::delete' => [self::directly(static function (ActingContext $actor): mixed {
            self::permissions()->delete(self::permission('posts:edit'), $actor);

            return null;
        }), [Actions::PERMISSION_DELETE], null];
        yield 'PolicyService::create' => [
            self::directly(static fn (ActingContext $actor): mixed => self::policies()->create('fresh', ['statements' => []], actor: $actor)),
            [Actions::POLICY_CREATE],
            null,
        ];
        yield 'PolicyService::createInline' => [
            self::directly(static fn (ActingContext $actor): mixed => self::policies()->createInline(self::user(), 'mine', ['statements' => []], actor: $actor)),
            [Actions::POLICY_CREATE],
            null,
        ];
        yield 'PolicyService::rename' => [
            self::directly(static fn (ActingContext $actor): mixed => self::policies()->rename(self::policy('reader', 'allow'), 'viewer', $actor)),
            [Actions::POLICY_RENAME],
            null,
        ];
        yield 'PolicyService::describe' => [
            self::directly(static fn (ActingContext $actor): mixed => self::policies()->describe(self::policy('reader', 'allow'), 'Reads', $actor)),
            [Actions::POLICY_UPDATE],
            null,
        ];
        yield 'PolicyService::rewrite' => [
            self::directly(static fn (ActingContext $actor): mixed => self::policies()->rewrite(self::policy('reader', 'allow'), ['statements' => []], $actor)),
            [Actions::POLICY_UPDATE],
            null,
        ];
        yield 'PolicyService::delete' => [self::directly(static function (ActingContext $actor): mixed {
            self::policies()->delete(self::policy('reader', 'allow'), $actor);

            return null;
        }), [Actions::POLICY_DELETE], null];
        yield 'BoundaryService::set' => [
            self::directly(static fn (ActingContext $actor): mixed => self::boundaries()->set(self::user(), self::policy('cap', 'allow'), actor: $actor)),
            [Actions::BOUNDARY_SET],
            null,
        ];
        yield 'BoundaryService::remove' => [static function (): \Closure {
            self::boundaries()->set(self::user(), self::policy('cap', 'allow'));

            return static fn (ActingContext $actor): mixed => self::boundaries()->remove(self::user(), actor: $actor);
        }, [Actions::BOUNDARY_REMOVE], null];
        yield 'BoundaryService::removeAll' => [static function (): \Closure {
            self::boundaries()->set(self::user(), self::policy('cap', 'allow'));

            return static fn (ActingContext $actor): mixed => self::boundaries()->removeAll(self::user(), $actor);
        }, [Actions::BOUNDARY_REMOVE], null];
        yield 'ResourcePolicyService::attach' => [
            self::directly(static fn (ActingContext $actor): mixed => self::resourcePolicies()->attach(self::sharing('allow'), ['posts', 7], actor: $actor)),
            [Actions::RESOURCE_POLICY_ATTACH],
            DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE,
        ];
        yield 'ResourcePolicyService::detach' => [static function (): \Closure {
            self::resourcePolicies()->attach(self::sharing('allow'), ['posts', 7]);

            return static fn (ActingContext $actor): mixed => self::resourcePolicies()->detach(self::sharing('allow'), ['posts', 7], actor: $actor);
        }, [Actions::RESOURCE_POLICY_DETACH], null];
        yield 'ResourcePolicyService::detach of a denying policy' => [static function (): \Closure {
            self::resourcePolicies()->attach(self::sharing('deny'), ['posts', 7]);

            return static fn (ActingContext $actor): mixed => self::resourcePolicies()->detach(self::sharing('deny'), ['posts', 7], actor: $actor);
        }, [Actions::RESOURCE_POLICY_DETACH], $unprovable];
        yield 'ResourcePolicyService::detachAll' => [static function (): \Closure {
            self::resourcePolicies()->attach(self::sharing('allow'), ['posts', 7]);

            return static fn (ActingContext $actor): mixed => self::resourcePolicies()->detachAll(['posts', 7], $actor);
        }, [Actions::RESOURCE_POLICY_DETACH], null];
    }

    /**
     * Called with an actor allowed every action, the grantable rights and
     * `authorization:administration.unbounded` included, and ranked above the
     * grantee, a call that may widen authority and that this release cannot
     * prove is refused before anything is written, and one that can only
     * narrow, or hands out only what the actor may grant, is made, as delegated
     * work, under the actions it decides, each change decided on the
     * operation's resource.
     *
     * @param  Setup  $setup
     * @param  list<string>  $actions
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $refusal
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('calls')]
    public function testEveryCallFollowsTheRulesInForce(\Closure $setup, array $actions, ?DecisionReason $refusal): void
    {
        $actor = self::administrator();
        $call  = $setup();

        if ($refusal !== null) {
            self::assertRefusedWithNothingWritten($call, $actor, $refusal, null);

            return;
        }

        $before    = self::snapshot();
        $decisions = \count(self::dispatched(DecisionEvaluated::class));
        $earlier   = self::changes();

        $call($actor);

        self::assertNotSame($before, self::snapshot());

        $made = \array_values(\array_filter(self::changes(), static fn (object $event): bool => !\in_array($event, $earlier, true)));

        self::assertSame($actions, \array_values(\array_unique(self::actionsSince($decisions))));
        self::assertNotSame([], $made);

        foreach ($made as $event) {
            self::assertTrue(\property_exists($event, 'operation'));
            self::assertFalse($event->operation->isTrusted);
            self::assertEquals($actor->principal(), $event->operation->actor);
        }
    }

    /**
     * Every delegated call that finds nothing to change, as a setup that
     * returns the call, and the actions it decides, in order: a revocation of
     * what the grantee does not hold, a removal of a boundary it does not have,
     * a revocation or removal of everything from a grantee that holds nothing,
     * a detachment of everything from a record with nothing attached, and a
     * sync whose kept rows are all held live.
     *
     * @return iterable<string, array{Setup, list<string>}>
     */
    public static function noChanges(): iterable
    {
        yield 'revokeRole by name, not held' => [
            self::directly(static fn (ActingContext $actor): mixed => self::grants()->revokeRole(self::user(), 'editor', $actor)),
            [Actions::ROLE_REVOKE],
        ];
        yield 'revokePermission, not held' => [
            self::directly(static fn (ActingContext $actor): mixed => self::grants()->revokePermission(self::user(), self::permission('posts:edit'), $actor)),
            [Actions::PERMISSION_REVOKE],
        ];
        yield 'RoleService::revokePermission by name, not carried' => [
            self::directly(static fn (ActingContext $actor): mixed => self::roles()->revokePermission(self::role('editor'), 'posts:edit', $actor)),
            [Actions::PERMISSION_REVOKE],
        ];
        yield 'BoundaryService::remove, none set' => [
            self::directly(static fn (ActingContext $actor): mixed => self::boundaries()->remove(self::user(), actor: $actor)),
            [Actions::BOUNDARY_REMOVE],
        ];
        yield 'BoundaryService::removeAll, none set' => [
            self::directly(static fn (ActingContext $actor): mixed => self::boundaries()->removeAll(self::user(), $actor)),
            [Actions::BOUNDARY_REMOVE],
        ];
        yield 'revokeAll, nothing held' => [
            self::directly(static fn (ActingContext $actor): mixed => self::grants()->revokeAll(self::user(), $actor)),
            [Actions::ROLE_REVOKE, Actions::PERMISSION_REVOKE, Actions::POLICY_DETACH, Actions::BOUNDARY_REMOVE],
        ];
        yield 'ResourcePolicyService::detachAll, nothing attached' => [
            self::directly(static fn (ActingContext $actor): mixed => self::resourcePolicies()->detachAll(['posts', 7], $actor)),
            [Actions::RESOURCE_POLICY_DETACH],
        ];
        yield 'syncRoles keeping what is held live' => [static function (): \Closure {
            self::grants()->grantRole(self::user(), self::role('editor'));

            return static fn (ActingContext $actor): mixed => self::grants()->syncRoles(self::user(), ['editor'], actor: $actor);
        }, [Actions::ROLE_GRANT]];
        yield 'syncRoles of nothing, nothing held' => [
            self::directly(static fn (ActingContext $actor): mixed => self::grants()->syncRoles(self::user(), [], actor: $actor)),
            [Actions::ROLE_REVOKE],
        ];
        yield 'RoleService::syncPermissions keeping what is carried live' => [static function (): \Closure {
            self::roles()->grantPermission(self::role('editor'), self::permission('posts:edit'));

            return static fn (ActingContext $actor): mixed => self::roles()->syncPermissions(self::role('editor'), ['posts:edit'], actor: $actor);
        }, [Actions::PERMISSION_GRANT]];
    }

    /**
     * A delegated call that finds nothing to change is still decided on its
     * actions, before it returns: an actor without them is refused, whether or
     * not anything was there to change, so it cannot learn what the grantee
     * holds by asking.
     *
     * @param  Setup  $setup
     * @param  list<string>  $actions
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('noChanges')]
    public function testACallThatChangesNothingIsRefusedWithoutItsAction(\Closure $setup, array $actions): void
    {
        $actor = self::administrator([]);
        $call  = $setup();

        self::assertRefusedWithNothingWritten($call, $actor, DecisionReason::NO_MATCH, $actions[0]);
    }

    /**
     * A delegated call that finds nothing to change, made by an actor allowed
     * every action, decides each of its actions, writes nothing and reports no
     * change.
     *
     * @param  Setup  $setup
     * @param  list<string>  $actions
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('noChanges')]
    public function testACallThatChangesNothingDecidesItsActions(\Closure $setup, array $actions): void
    {
        $actor     = self::administrator();
        $call      = $setup();
        $before    = self::snapshot();
        $decisions = \count(self::dispatched(DecisionEvaluated::class));
        $changes   = \count(self::changes());

        $call($actor);

        self::assertSame($before, self::snapshot());
        self::assertSame($actions, self::actionsSince($decisions));
        self::assertCount($changes, self::changes());
    }

    /**
     * A screen that checks the same action on the same operation resource gets
     * the decision the service makes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAScreenAndTheServiceAgree(): void
    {
        $actor = self::administrator([Actions::ROLE_GRANT, Actions::ROLE_REVOKE]);
        $role  = self::role('editor');

        self::roles()->grantPermission($role, self::permission('posts:edit'));

        $grant       = OperationResource::grant(Actions::ROLE_GRANT, self::user(), $role, GrantScope::platform());
        $revoke      = OperationResource::revoke(Actions::ROLE_REVOKE, self::user(), $role, GrantScope::platform());
        $grantScreen = $actor->check($grant);
        $refusal     = self::refusalOf(static fn (): mixed => self::grants()->grantRole(self::user(), $role, actor: $actor));

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertEquals([$grantScreen->effect, $grantScreen->reason, $grantScreen->stage, $grantScreen->trace], [
            $refusal->getDecision()?->effect, $refusal->getDecision()?->reason, $refusal->getDecision()?->stage, $refusal->getDecision()?->trace,
        ]);

        self::grants()->grantRole(self::user(), $role);

        self::assertTrue($actor->check($revoke)->isAllowed());
        self::assertSame(1, self::grants()->revokeRole(self::user(), $role, $actor));
    }

    /**
     * A batch is atomic: every item is decided before any is written, so a sync
     * whose revocation is allowed and whose grant is refused writes and reports
     * nothing, and decides the grant without the revocation having been made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABatchIsDecidedWholeBeforeAnythingIsWritten(): void
    {
        $actor = self::administrator([Actions::ROLE_GRANT, Actions::ROLE_REVOKE]);

        self::grants()->grantRole(self::user(), self::role('editor'));
        self::roles()->grantPermission(self::role('author'), self::permission('posts:edit'));

        $decisions = \count(self::dispatched(DecisionEvaluated::class));

        $sync = static fn (ActingContext $actor): mixed => self::grants()->syncRoles(self::user(), [self::role('author')], actor: $actor);

        self::assertRefusedWithNothingWritten($sync, $actor, DecisionReason::ADMINISTRATION_NOT_GRANTABLE, Actions::ROLE_GRANT);
        self::assertSame([Actions::ROLE_GRANT], self::actionsSince($decisions));
    }

    /**
     * Revoking everything decides the revocation of every grant before any is
     * written, so a boundary among them, whose removal widens, leaves every
     * grant held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingEverythingDecidesEveryItemFirst(): void
    {
        $actor = self::administrator([Actions::ROLE_REVOKE, Actions::PERMISSION_REVOKE, Actions::BOUNDARY_REMOVE]);

        self::grants()->grantRole(self::user(), self::role('editor'));
        self::grants()->grantPermission(self::user(), self::permission('posts:edit'));
        self::boundaries()->set(self::user(), self::policy('cap', 'allow'));

        $decisions = \count(self::dispatched(DecisionEvaluated::class));

        $revokeAll = static fn (ActingContext $actor): mixed => self::grants()->revokeAll(self::user(), $actor);

        self::assertRefusedWithNothingWritten($revokeAll, $actor, DecisionReason::ADMINISTRATION_UNPROVABLE, Actions::BOUNDARY_REMOVE);
        self::assertSame(1, DB::table('authorizable_roles')->where('authorizable_id', 'user-1')->count());
        self::assertSame(1, DB::table('authorizable_boundaries')->count());
        Event::assertNotDispatched(RoleRevoked::class);
        Event::assertNotDispatched(PermissionRevoked::class);
        self::assertSame([Actions::ROLE_REVOKE, Actions::PERMISSION_REVOKE, Actions::BOUNDARY_REMOVE], self::actionsSince($decisions));
    }

    /**
     * A delegated change made while impersonating is refused as impersonating
     * unless the actor is allowed `authorization:administration.impersonated`,
     * and its events then carry both actors.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnImpersonatedChangeNeedsTheImpersonatedRight(): void
    {
        $actor   = self::administrator([Actions::PERMISSION_REVOKE])->impersonatedBy(new Reference('support', '9'));
        $holder  = StubIdentity::query()->findOrFail('admin-1');
        $granted = static fn (): mixed => self::grants()->grantPermission(self::user(), self::permission('posts:edit'));

        $granted();

        $refusal = self::refusalOf(static fn (): mixed => self::grants()->revokePermission(self::user(), 'posts:edit', $actor));

        self::assertSame(DecisionReason::ADMINISTRATION_IMPERSONATING, $refusal instanceof AuthorizationException ? $refusal->getReason() : null);
        self::assertSame(1, DB::table('authorizable_permissions')->where('authorizable_id', 'user-1')->count());

        self::grants()->grantPermission($holder, self::permission(Actions::ADMINISTRATION_IMPERSONATED));

        self::assertSame(1, self::grants()->revokePermission(self::user(), 'posts:edit', $actor));
        Event::assertDispatched(PermissionRevoked::class, static fn (PermissionRevoked $event): bool => $event->operation->impersonator?->id === '9'
            && $event->operation->actor?->id                                                                                                 === 'admin-1');
    }

    /**
     * The events of a delegated write carry the actor's principal and identity
     * references, the delegated mode, the actions and the operation's id, which
     * every decision made for the write names as its resource.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheEventsAndDecisionsShareTheOperationsId(): void
    {
        $actor = self::administrator();

        self::grants()->grantRole(self::user(), self::role('editor'));
        self::grants()->grantRole(self::user(), self::role('author'));

        $mark = \count(self::dispatched(DecisionEvaluated::class));

        self::grants()->syncRoles(self::user(), [], actor: $actor);

        $events    = self::dispatched(RoleRevoked::class);
        $decisions = \array_slice(self::dispatched(DecisionEvaluated::class), $mark);

        self::assertCount(2, $events);
        self::assertCount(2, $decisions);

        foreach ($events as $event) {
            self::assertSame($events[0]->operation->id, $event->operation->id);
            self::assertEquals($actor->principal(), $event->operation->actor);
            self::assertEquals($actor->identity(), $event->operation->identity);
            self::assertFalse($event->operation->isTrusted);
            self::assertSame([Actions::ROLE_GRANT, Actions::ROLE_REVOKE], $event->operation->actions);
        }

        foreach ($decisions as $decision) {
            self::assertSame(OperationResource::TYPE . ':' . $events[0]->operation->id, $decision->resource);
            self::assertSame($actor->subject->subject, $decision->principal);
        }
    }

    /**
     * Assert the call, made as the actor, is refused for the reason, after the
     * action is decided when one is named, and leaves every table as it was and
     * dispatches no change event.
     *
     * @param  \Closure(\SineMacula\Laravel\Authorization\Administration\ActingContext): mixed  $call
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @param  string|null  $action
     * @return void
     */
    private static function assertRefusedWithNothingWritten(\Closure $call, ActingContext $actor, DecisionReason $reason, ?string $action): void
    {
        $before  = self::snapshot();
        $changes = \count(self::changes());
        $refusal = self::refusalOf(static fn (): mixed => $call($actor));

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame($reason, $refusal->getReason());
        self::assertSame($before, self::snapshot());
        self::assertCount($changes, self::changes());
        self::assertSame($refusal->getDecision(), \array_reverse(self::dispatched(AuthorizationFailed::class))[0]->decision);

        if ($action === null) {
            return;
        }

        self::assertSame($action, \array_reverse(self::dispatched(DecisionEvaluated::class))[0]->action);
    }

    /**
     * Return a setup that makes nothing first and returns the call.
     *
     * @param  \Closure(\SineMacula\Laravel\Authorization\Administration\ActingContext): mixed  $call
     * @return Setup
     */
    private static function directly(\Closure $call): \Closure
    {
        return static fn (): \Closure => $call;
    }

    /**
     * Return the change events dispatched so far: every package event but the
     * decisions and the refusals.
     *
     * @return list<object>
     */
    private static function changes(): array
    {
        $isChange = static fn (object $event): bool => !$event instanceof DecisionEvaluated && !$event instanceof AuthorizationFailed;

        return \array_values(\array_filter(self::dispatched(AuthorizationEvent::class), $isChange));
    }

    /**
     * Return the action of each decision reported after the first so many, in
     * order.
     *
     * @param  int  $mark
     * @return list<string>
     */
    private static function actionsSince(int $mark): array
    {
        return \array_map(static fn (DecisionEvaluated $event): string => $event->action, \array_slice(self::dispatched(DecisionEvaluated::class), $mark));
    }

    /**
     * Return the events of the class dispatched so far, in order.
     *
     * @template TEvent of object
     *
     * @param  class-string<TEvent>  $class
     * @return list<TEvent>
     */
    private static function dispatched(string $class): array
    {
        $events = [];

        /** @var array<string, list<array{0: object}>> $dispatched */
        $dispatched = Event::dispatchedEvents(); // @phpstan-ignore staticMethod.notFound

        foreach ($dispatched as $calls) {
            foreach ($calls as [$event]) {
                if (!$event instanceof $class) {
                    continue;
                }

                $events[] = $event;
            }
        }

        return $events;
    }

    /**
     * Return every row of every table a management service writes, each as
     * JSON, sorted, to tell whether anything was written.
     *
     * @return array<string, list<string>>
     *
     * @throws \JsonException
     */
    private static function snapshot(): array
    {
        $rows = [];

        foreach (self::TABLES as $table) {
            $encoded = [];

            foreach (DB::table($table)->get() as $row) {
                $encoded[] = \json_encode((array) $row, \JSON_THROW_ON_ERROR);
            }

            \sort($encoded);

            $rows[$table] = $encoded;
        }

        return $rows;
    }

    /**
     * Return the grantee the calls change, created on first use.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function user(): StubIdentity
    {
        return StubIdentity::query()->firstOrCreate(['id' => 'user-1']);
    }

    /**
     * Return the platform role of the name, created on first use.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(string $name): Role
    {
        return Role::query()->firstOrCreate(['name' => $name]);
    }

    /**
     * Return the platform permission of the name, created on first use.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function permission(string $name): Permission
    {
        return Permission::query()->firstOrCreate(['name' => $name]);
    }

    /**
     * Return the policy of the name, one statement with the effect, created on
     * first use.
     *
     * @param  string  $name
     * @param  string  $effect
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, string $effect): Policy
    {
        return Policy::query()->where('name', $name)->first()
            ?? Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => $effect, 'actions' => ['posts:*']]]]]);
    }

    /**
     * Return the resource policy whose one statement, of the effect, shares
     * posts with the user or denies reading them to everyone, created on first
     * use.
     *
     * @param  string  $effect
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function sharing(string $effect): Policy
    {
        $statement = ['effect' => $effect, 'actions' => ['posts:read'], ...($effect === 'allow' ? ['principals' => ['user:1']] : [])];

        return Policy::query()->where('name', "sharing-{$effect}")->first() ?? Policy::create(['name' => "sharing-{$effect}", 'document' => ['statements' => [$statement]]]);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        return app(GrantService::class);
    }

    /**
     * Return the role service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleService
     */
    private static function roles(): RoleService
    {
        return app(RoleService::class);
    }

    /**
     * Return the permission service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\PermissionService
     */
    private static function permissions(): PermissionService
    {
        return app(PermissionService::class);
    }

    /**
     * Return the policy service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\PolicyService
     */
    private static function policies(): PolicyService
    {
        return app(PolicyService::class);
    }

    /**
     * Return the boundary service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\BoundaryService
     */
    private static function boundaries(): BoundaryService
    {
        return app(BoundaryService::class);
    }

    /**
     * Return the resource policy service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\ResourcePolicyService
     */
    private static function resourcePolicies(): ResourcePolicyService
    {
        return app(ResourcePolicyService::class);
    }
}
