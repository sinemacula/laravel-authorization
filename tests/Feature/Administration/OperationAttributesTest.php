<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationAttributes;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `OperationAttributes`, the package's attribute provider of
 * administration operation resources.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationAttributes::class)]
final class OperationAttributesTest extends TestCase
{
    /**
     * The provider declares every key an operation resource offers, each with
     * its type, and the context key catalogue holds them under `resource`.
     *
     * @return void
     */
    public function testDeclaresEveryKeyItOffers(): void
    {
        $attributes = (new OperationAttributes)->attributes();

        self::assertInstanceOf(ResourceAttributeProvider::class, new OperationAttributes);
        self::assertSame(ContextKeyType::STRING, $attributes['action']);
        self::assertSame(ContextKeyType::BOOL, $attributes['narrowing']);
        self::assertSame(ContextKeyType::BOOL, $attributes['unchanged']);
        self::assertSame(ContextKeyType::BOOL, $attributes['subtree']);
        self::assertSame(ContextKeyType::TIME, $attributes['expires_at']);
        self::assertSame(ContextKeyType::NUMBER, $attributes['change.rank']);
        self::assertSame(ContextKeyType::BOOL, $attributes['impersonated']);
        self::assertCount(26, $attributes);

        $strings = ['target_type', 'target_id', 'role', 'permission', 'policy', 'grantee_type', 'grantee_id', 'application', 'digest', 'change.name', 'change.description'];

        foreach ([...$strings, 'change.parent'] as $key) {
            self::assertSame(ContextKeyType::STRING, $attributes[$key], $key);
        }

        foreach (['change.guard', 'change.category', 'change.digest', 'change.owner_type', 'change.owner_id', 'impersonator_type', 'impersonator_id'] as $key) {
            self::assertSame(ContextKeyType::STRING, $attributes[$key], $key);
        }

        /** @var \SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue $catalogue */
        $catalogue = $this->app?->make(ContextKeyCatalogue::class);

        self::assertNotNull($catalogue->find('resource.grantee_type'));
        self::assertNotNull($catalogue->find('resource.change.name'));
    }

    /**
     * The values are those of the operation resource the reference hands on;
     * any other reference of the type has none.
     *
     * @return void
     */
    public function testOffersTheAttributesOfTheOperationResource(): void
    {
        $edit      = Permission::create(['name' => 'posts:edit']);
        $operation = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, new Reference('user', '1'), $edit, GrantScope::platform());

        self::assertSame($operation->attributes(), (new OperationAttributes)->values($operation->toResourceReference(), null));
        self::assertSame([], (new OperationAttributes)->values(ResourceReference::record(OperationResource::TYPE, 'forged'), null));
    }

    /**
     * A policy reads whether the change changes nothing, under
     * `resource.unchanged`: an actor allowed only calls that change nothing
     * makes one, and is refused a change that would revoke.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyReadsWhetherTheChangeChangesNothing(): void
    {
        $admin = StubIdentity::create(['id' => 'admin-1']);

        config(['authorization.rank.enabled' => false]);

        $admin->attachPolicy(Policy::create(['name' => 'no-op', 'document' => ['statements' => [[
            'effect'     => PolicyEffect::ALLOW->value,
            'actions'    => [PackagePermissions::PERMISSION_REVOKE],
            'resources'  => [OperationResource::TYPE . ':*'],
            'conditions' => ['eq' => ['resource.unchanged' => true]],
        ]]]]));

        $actor     = ActingContext::for($admin);
        $grantee   = new Reference('user', '1');
        $unchanged = OperationResource::unchanged(PackagePermissions::PERMISSION_REVOKE, $grantee, null, GrantScope::platform());
        $revoke    = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $grantee, Permission::create(['name' => 'posts:edit']), GrantScope::platform());

        self::assertTrue((new OperationAttributes)->values($unchanged->toResourceReference(), null)['unchanged']);
        self::assertTrue($actor->check($unchanged)->isAllowed());
        self::assertSame(DecisionReason::CONDITION_FAILED, $actor->check($revoke)->reason);
    }

    /**
     * A policy conditions an administration action on what the operation names,
     * under `resource`, through the one decision path.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyConditionsOnTheOperation(): void
    {
        $admin = StubIdentity::create(['id' => 'admin-1']);

        // The grantee is named by a reference alone, whose rank cannot be read,
        // so rank is off: the attributes are what this test is about.
        config(['authorization.rank.enabled' => false]);

        $admin->attachPolicy(Policy::create(['name' => 'revoker', 'document' => ['statements' => [[
            'effect'     => PolicyEffect::ALLOW->value,
            'actions'    => [PackagePermissions::PERMISSION_REVOKE],
            'resources'  => [OperationResource::TYPE . ':*'],
            'conditions' => ['eq' => ['resource.permission' => 'posts:edit', 'resource.grantee_type' => 'user', 'resource.narrowing' => true]],
        ]]]]));

        $actor = ActingContext::for($admin);
        $edit  = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, new Reference('user', '1'), Permission::create(['name' => 'posts:edit']), GrantScope::platform());
        $read  = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, new Reference('user', '1'), Permission::create(['name' => 'posts:read']), GrantScope::platform());

        self::assertTrue($actor->check($edit)->isAllowed());
        self::assertSame(DecisionReason::CONDITION_FAILED, $actor->check($read)->reason);
    }
}
