<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use Tests\Feature\Stubs\CustomRole;
use Tests\TestCase;

/**
 * Feature tests pinning the role class the observer's hierarchy cycle check
 * resolves.
 *
 * With `authorization.models.role` pointed at an application subclass, the
 * proposed-parent lookup the observer runs before refusing a cycle hydrates
 * that subclass, never the shipped `Role`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RoleObserver::class)]
#[CoversClass(RoleHierarchyCycleException::class)]
final class RoleObserverTest extends TestCase
{
    /**
     * Point `authorization.models.role` at the subclass stub.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.models.role', CustomRole::class);
    }

    /**
     * Re-parenting a role under its own descendant is refused with the proposed
     * parent's name, read back through the configured subclass.
     *
     * @return void
     */
    public function testCycleCheckLooksUpProposedParentThroughConfiguredRoleClass(): void
    {
        $root  = $this->makeRole('admin');
        $child = $this->makeRole('editor', $root->id);

        $hydrated = $this->recordHydratedRoleClasses();

        $root->parent_id = $child->id;

        try {
            $root->save();
            self::fail('RoleHierarchyCycleException was not thrown.');
        } catch (RoleHierarchyCycleException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('admin', $exception->getRoleName());
            self::assertSame('editor', $exception->getProposedParentName());
            self::assertSame([CustomRole::class, CustomRole::class], $hydrated->getArrayCopy());
        }
    }

    /**
     * Record the class of every role model hydrated from here on.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordHydratedRoleClasses(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $hydrated */
        $hydrated = new \ArrayObject;

        Event::listen('eloquent.retrieved: *', static function (string $event, array $payload) use ($hydrated): void {
            if (!$payload[0] instanceof Role) {
                return;
            }

            $hydrated->append($payload[0]::class);
        });

        return $hydrated;
    }

    /**
     * Create a role through the configured subclass.
     *
     * @param  string  $name
     * @param  string|null  $parentId
     * @return \Tests\Feature\Stubs\CustomRole
     */
    private function makeRole(string $name, ?string $parentId = null): CustomRole
    {
        return CustomRole::query()->create([
            'name'      => $name,
            'guard'     => 'web',
            'parent_id' => $parentId,
        ]);
    }
}
