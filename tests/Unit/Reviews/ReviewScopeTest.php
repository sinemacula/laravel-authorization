<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\Enums\ScopeSelection;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Unit tests for the scope of an access review: what applies in a tenant or at
 * the platform, what is rooted within a tenant, or everywhere, each with its
 * application, and the reach each is admitted across.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReviewScope::class)]
final class ReviewScopeTest extends TestCase
{
    /**
     * A review of what applies in a tenant names the tenant and its
     * application, and is admitted at the tenant's node alone; at the platform,
     * across every tenant.
     *
     * @return void
     */
    public function testAReviewOfWhatAppliesInATenantIsAdmittedAtItsNode(): void
    {
        $tenant = new Reference('tenant', 't1');
        $scope  = ReviewScope::appliesIn($tenant, ApplicationSelector::named('web'));
        $reach  = $scope->reach();

        self::assertSame([ScopeSelection::APPLIES_IN, $tenant, 'web'], [$scope->selection, $scope->tenant, $scope->application->application]);
        self::assertSame([$tenant, 'web', false], [$reach->tenant, $reach->application, $reach->includeSubtree]);

        $platform = ReviewScope::appliesIn(null, ApplicationSelector::any())->reach();

        self::assertSame([null, null, true], [$platform->tenant, $platform->application, $platform->includeSubtree]);
    }

    /**
     * A review rooted within a tenant reaches the tenants below it, in any
     * application unless told; one of everywhere reaches the platform.
     *
     * @return void
     */
    public function testBroadReviewsReachBelowAndEverywhere(): void
    {
        $tenant = new Reference('tenant', 't1');
        $rooted = ReviewScope::rootedWithin($tenant);

        self::assertSame([ScopeSelection::ROOTED_WITHIN, $tenant, 'any'], [$rooted->selection, $rooted->tenant, $rooted->application->selection()]);
        self::assertSame([$tenant, null, true], [$rooted->reach()->tenant, $rooted->reach()->application, $rooted->reach()->includeSubtree]);
        self::assertSame('none', ReviewScope::rootedWithin($tenant, ApplicationSelector::none())->application->selection());

        $everywhere = ReviewScope::everywhere();

        self::assertSame([ScopeSelection::EVERYWHERE, null, 'any'], [$everywhere->selection, $everywhere->tenant, $everywhere->application->selection()]);
        self::assertSame(
            [null, 'web', true],
            [
                ReviewScope::everywhere(ApplicationSelector::named('web'))->reach()->tenant,
                ReviewScope::everywhere(ApplicationSelector::named('web'))->reach()->application,
                ReviewScope::everywhere()->reach()->includeSubtree,
            ],
        );
    }

    /**
     * A tenant model is named by its morph type and key, and one without a key
     * is refused.
     *
     * @return void
     */
    public function testATenantModelIsNamedByItsReference(): void
    {
        $tenant = StubTenant::query()->create(['id' => 't1']);

        self::assertSame(
            [$tenant->getMorphClass(), 't1'],
            [ReviewScope::rootedWithin($tenant)->tenant?->type, ReviewScope::appliesIn($tenant, ApplicationSelector::none())->tenant?->id],
        );

        $this->expectException(InvalidTenantException::class);

        ReviewScope::rootedWithin(new StubTenant);
    }
}
