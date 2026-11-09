<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewAttributes;
use SineMacula\Laravel\Authorization\Reviews\ReviewResource;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Unit tests for the package's attribute provider of review resources.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReviewAttributes::class)]
final class ReviewAttributesTest extends TestCase
{
    /**
     * It declares every key a review resource names, each a string but whether
     * the reviewer is impersonated, a boolean.
     *
     * @return void
     */
    public function testItDeclaresEveryKeyAsAString(): void
    {
        $keys = [
            'query',
            'scope',
            'application_selection',
            'application',
            'target_type',
            'target_id',
            'subject_type',
            'subject_id',
            'actor_type',
            'actor_id',
            'impersonator_type',
            'impersonator_id',
        ];

        self::assertSame([...\array_fill_keys($keys, ContextKeyType::STRING), 'impersonated' => ContextKeyType::BOOL], (new ReviewAttributes)->attributes());
    }

    /**
     * It supplies a review resource's attributes, and none for any other
     * resource of the type.
     *
     * @return void
     */
    public function testItSuppliesAReviewResourcesAttributes(): void
    {
        $review = new ReviewResource(ReviewKind::EXPIRING, ReviewScope::everywhere());

        self::assertSame($review->attributes(), (new ReviewAttributes)->values($review->toResourceReference(), null));
        self::assertSame([], (new ReviewAttributes)->values(ResourceReference::record(ReviewResource::TYPE, 'holders'), null));
    }
}
