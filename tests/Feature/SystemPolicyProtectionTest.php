<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException;
use SineMacula\Laravel\Authorization\Models\Policy;
use Tests\TestCase;

/**
 * Feature coverage for the system-policy protection flag.
 *
 * `is_system = true` blocks the next delete or rename on the
 * instance unless `forceSystem()` is called first; the bypass is
 * per-instance, in-memory, and single-use — it does not persist
 * across `$policy->fresh()` hydrations and re-arms on the next
 * protected mutation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Policy::class)]
#[CoversClass(SystemPolicyProtectedException::class)]
final class SystemPolicyProtectionTest extends TestCase
{
    /**
     * Deleting a system policy without the escape hatch is
     * refused.
     *
     * @return void
     */
    public function testDeletingSystemPolicyIsRefused(): void
    {
        $policy = $this->makeSystemPolicy('break-glass');

        try {
            $policy->delete();
            self::fail('Expected SystemPolicyProtectedException was not thrown.');
        } catch (SystemPolicyProtectedException $exception) {
            self::assertSame('break-glass', $exception->getPolicyName());
            self::assertSame('delete', $exception->getOperation());
        }

        self::assertNotNull(Policy::query()->find($policy->getKey()));
    }

    /**
     * Renaming a system policy without the escape hatch is
     * refused.
     *
     * @return void
     */
    public function testRenamingSystemPolicyIsRefused(): void
    {
        $policy = $this->makeSystemPolicy('system-audit');

        try {
            $policy->name = 'rebranded-audit';
            $policy->save();
            self::fail('Expected SystemPolicyProtectedException was not thrown.');
        } catch (SystemPolicyProtectedException $exception) {
            self::assertSame('system-audit', $exception->getPolicyName());
            self::assertSame('rename', $exception->getOperation());
        }

        self::assertSame('system-audit', $policy->fresh()?->name);
    }

    /**
     * `forceSystem()` unlocks the next delete.
     *
     * @return void
     */
    public function testForceSystemAllowsDelete(): void
    {
        $policy = $this->makeSystemPolicy('retired-policy');

        $policy->forceSystem()->delete();

        self::assertNull(Policy::query()->find($policy->getKey()));
    }

    /**
     * `forceSystem()` unlocks the next rename.
     *
     * @return void
     */
    public function testForceSystemAllowsRename(): void
    {
        $policy = $this->makeSystemPolicy('legacy-name');

        $policy->forceSystem();
        $policy->name = 'new-canonical-name';
        $policy->save();

        self::assertSame('new-canonical-name', $policy->fresh()?->name);
    }

    /**
     * Non-rename updates — description, document swap — pass
     * without needing the escape hatch.
     *
     * @return void
     */
    public function testDescriptionUpdateOnSystemPolicyPasses(): void
    {
        $policy = $this->makeSystemPolicy('break-glass');

        $policy->description = 'Break-glass — elevated platform access.';
        $policy->save();

        self::assertSame(
            'Break-glass — elevated platform access.',
            $policy->fresh()?->description,
        );
    }

    /**
     * The bypass is single-use — after one protected mutation
     * the next one re-arms.
     *
     * @return void
     */
    public function testForceSystemIsSingleUse(): void
    {
        $policy = $this->makeSystemPolicy('volatile-policy');

        $policy->forceSystem();
        $policy->name = 'renamed-once';
        $policy->save();

        self::assertSame('renamed-once', $policy->fresh()?->name);

        $this->expectException(SystemPolicyProtectedException::class);

        $policy->name = 'second-rename';
        $policy->save();
    }

    /**
     * `forceSystem()` is consumed by an intervening non-protected
     * save (e.g. a description update), so a subsequent rename
     * without re-arming the bypass is refused.
     *
     * @return void
     */
    public function testBypassDoesNotHopAcrossUnrelatedSave(): void
    {
        $policy = $this->makeSystemPolicy('break-glass');

        $policy->forceSystem();
        $policy->description = 'Updated description.';
        $policy->save();

        $this->expectException(SystemPolicyProtectedException::class);

        $policy->name = 'renamed-without-bypass';
        $policy->save();
    }

    /**
     * Non-system policies behave as before — no protection, no
     * bypass required.
     *
     * @return void
     */
    public function testNonSystemPoliciesDeleteFreely(): void
    {
        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'ordinary-policy',
            'document' => [
                'statements' => [
                    [
                        'effect'    => 'allow',
                        'actions'   => ['posts:read'],
                        'resources' => ['arn:posts:*'],
                    ],
                ],
            ],
        ]);

        self::assertFalse((bool) $policy->is_system);

        $policy->delete();

        self::assertNull(Policy::query()->find($policy->getKey()));
    }

    /**
     * Create a system-flagged policy with a minimal valid
     * document for protection scenarios.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private function makeSystemPolicy(string $name): Policy
    {
        return Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => $name,
            'document' => [
                'statements' => [
                    [
                        'effect'    => 'allow',
                        'actions'   => ['*:*'],
                        'resources' => ['*'],
                    ],
                ],
            ],
            'is_system' => true,
        ]);
    }
}
