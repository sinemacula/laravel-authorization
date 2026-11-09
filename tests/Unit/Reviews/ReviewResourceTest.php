<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewResource;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\TestCase;

/**
 * Unit tests for the resource a review's admission is decided on: the question,
 * what it is about by reference, and the reviewed scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReviewResource::class)]
final class ReviewResourceTest extends TestCase
{
    /**
     * Its reference is a record of the review type keyed by the question, in
     * the reviewed tenant, handing the resource on; none at the platform.
     *
     * @return void
     */
    public function testItsReferenceNamesTheQuestionInTheReviewedTenant(): void
    {
        $tenant   = new Reference('tenant', 't1');
        $review   = new ReviewResource(ReviewKind::HOLDERS, ReviewScope::rootedWithin($tenant));
        $resource = $review->toResourceReference();

        self::assertInstanceOf(AuthorizableResource::class, $review);
        self::assertSame('authorization:review', ReviewResource::TYPE);
        self::assertSame(
            ['authorization:review:holders', 'authorization:review', 'holders', $tenant, null, $review],
            [$resource->identifier, $resource->type, $resource->id, $resource->tenant, $resource->model, $resource->source],
        );
        self::assertNull((new ReviewResource(ReviewKind::EXPIRING, ReviewScope::everywhere()))->toResourceReference()->tenant);
        self::assertSame([$tenant, true], [$review->reach()->tenant, $review->reach()->includeSubtree]);
    }

    /**
     * Its attributes name the question, the scope, the application and every
     * reference the review is about, leaving out what it has none of.
     *
     * @return void
     */
    public function testItsAttributesNameWhatTheReviewIsAbout(): void
    {
        $full = new ReviewResource(
            ReviewKind::GRANTED_BY,
            ReviewScope::appliesIn(new Reference('tenant', 't1'), ApplicationSelector::named('web')),
            new Reference('role', 'r'),
            new Reference('user', 'u'),
            new Reference('user', 'a'),
        );

        self::assertSame([
            'query'                 => 'granted_by',
            'scope'                 => 'applies_in',
            'application_selection' => 'named',
            'application'           => 'web',
            'target_type'           => 'role',
            'target_id'             => 'r',
            'subject_type'          => 'user',
            'subject_id'            => 'u',
            'actor_type'            => 'user',
            'actor_id'              => 'a',
        ], $full->attributes());

        self::assertSame(
            ['query' => 'holdings', 'scope' => 'everywhere', 'application_selection' => 'any'],
            (new ReviewResource(ReviewKind::HOLDINGS, ReviewScope::everywhere()))->attributes(),
        );
    }

    /**
     * The resource of a query names its question, scope, target, subject and
     * actor.
     *
     * @return void
     */
    public function testTheResourceOfAQueryNamesWhatItIsAbout(): void
    {
        $scope   = ReviewScope::everywhere();
        $role    = new Reference((new Role)->getMorphClass(), 'r');
        $holders = ReviewResource::of(ReviewQuery::holders($role, $scope));

        self::assertSame([ReviewKind::HOLDERS, $scope, 'r', null, null], [$holders->kind, $holders->scope, $holders->target?->id, $holders->subject, $holders->actor]);
        self::assertSame('u', ReviewResource::of(ReviewQuery::holdings(new Subject(new Reference('user', 'u'), null), $scope))->subject?->id);
        self::assertSame('a', ReviewResource::of(ReviewQuery::grantedBy(new Reference('user', 'a'), $scope))->actor?->id);
    }
}
