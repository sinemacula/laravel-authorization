<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Administration\RoleParent;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `RoleParent`: a delegated change of a role's parent hands
 * the parent's whole authority to every holder of the role.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleParent::class)]
final class RoleParentTest extends TestCase
{
    /**
     * Keeping the parent changes nothing; clearing one whose chain carries no
     * deny only narrows; replacing or clearing one whose chain does, or one
     * that is gone, lifts what cannot be bounded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParentIsTakenAwayOnlyWhenItLiftsNoDeny(): void
    {
        $plain   = Role::query()->create(['name' => 'plain']);
        $guarded = Role::query()->create(['name' => 'guarded']);
        $above   = Role::query()->create(['name' => 'above']);

        RoleService::instance()?->setParent($guarded, $above);
        self::grants()->attachPolicy($above, Policy::create(['name' => 'denying', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:*']]]]]));

        $underPlain   = Role::query()->create(['name' => 'under-plain', 'parent_id' => $plain->id]);
        $underGuarded = Role::query()->create(['name' => 'under-guarded', 'parent_id' => $guarded->id]);
        $orphan       = (new Role)->forceFill(['id' => '01a1b0c0-0000-7000-8000-00000000beef', 'name' => 'orphan', 'parent_id' => '01a1b0c0-0000-7000-8000-00000000dead']);

        self::assertNull(self::refusal($underPlain, $plain->id));
        self::assertNull(self::refusal($underPlain, null));
        self::assertNull(self::refusal($underPlain, ''));
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::refusal($underGuarded, null));
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::refusal($underGuarded, $plain->id));
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::refusal($orphan, null));
    }

    /**
     * Setting a parent hands its whole authority to the role's holders: with
     * none, it widens no one; with one, the actor must be able to hand out
     * every permission of the parent's chain, so one it does not hold is not
     * grantable, and one it holds but cannot prove contained, with no source
     * readable, is unprovable; a parent whose chain cannot be read is
     * unprovable too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParentSetHandsItsAuthorityToEveryHolder(): void
    {
        $role   = Role::query()->create(['name' => 'editor']);
        $root   = Role::query()->create(['name' => 'root']);
        $parent = Role::query()->create(['name' => 'parent', 'parent_id' => $root->id]);

        RoleService::instance()?->grantPermission($root, Permission::query()->create(['name' => 'posts:delete']));

        self::assertNull(self::refusal($role, $parent->id));

        self::grants()->grantRole(StubIdentity::query()->create(['id' => 'holder']), $role);

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, self::refusal($role, $parent->id));
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::refusal($role, '01a1b0c0-0000-7000-8000-00000000dead'));

        self::grants()->grantPermission(self::actor(), Permission::query()->firstOrCreate(['name' => 'posts:*']));

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::refusal($role, $parent->id));
    }

    /**
     * Return why giving the role the parent is refused, the actor ranked most
     * senior and every further check allowed, no source read.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  mixed  $parent
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     *
     * @throws \Throwable
     */
    private static function refusal(Role $role, mixed $parent): ?DecisionReason
    {
        $actor     = self::actor();
        $operation = OperationResource::definition(PackagePermissions::ROLE_PARENT_SET, $role, ['parent' => \is_string($parent) ? $parent : null]);
        $checks    = new FurtherChecks(new Subject($actor, $actor), static fn (): Decision => Decision::allow(DecisionStage::ALLOW), static fn (): null => null);

        return RoleParent::refusal($operation, $role, $parent, $operation->toResourceReference(), $checks);
    }

    /**
     * Return the actor, holding the most senior rank, created on first use.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function actor(): StubIdentity
    {
        $actor = StubIdentity::query()->firstOrCreate(['id' => 'admin']);

        if (!$actor->hasRole('chief')) {
            self::grants()->grantRole($actor, Role::query()->create(['name' => 'chief', 'rank' => 0]));
        }

        return $actor;
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
}
