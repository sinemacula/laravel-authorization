<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckBatch;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\TestCase;

/**
 * Performance budget for a single check, which the Gate hook and Blade's `@can`
 * make for every ability a page asks about: a check on its own is decided as it
 * stands, reading nothing ahead and holding nothing for later, so it costs what
 * the decision costs, not the machinery of a bulk check. The budget bounds
 * 1,000 warm checks of each kind well above the observed cost (about 15µs
 * each), to absorb CI variance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckBatch::class)]
final class SingleCheckBudgetTest extends TestCase
{
    /**
     * 1,000 warm checks with no resource, and 1,000 on an opaque one, must each
     * complete in under 150ms.
     *
     * @return void
     */
    public function testAWarmCheckCostsWhatItsDecisionCosts(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user));
        $this->app?->forgetInstance('authorization');

        Authorization::clearResolvedInstance('authorization');

        foreach ([null, 'posts/1'] as $resource) {
            self::assertTrue(Authorization::check('posts:read', $resource)->isAllowed());

            $start = \microtime(true);

            for ($i = 0; $i < 1000; $i++) {
                Authorization::check('posts:read', $resource);
            }

            $elapsed = \microtime(true) - $start;

            self::assertLessThan(0.15, $elapsed, "Single check budget exceeded ({$elapsed}s for 1,000 checks).");
        }
    }
}
