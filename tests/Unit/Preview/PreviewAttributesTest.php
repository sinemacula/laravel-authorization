<?php

declare(strict_types = 1);

namespace Tests\Unit\Preview;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Preview\PreviewAttributes;
use SineMacula\Laravel\Authorization\Preview\PreviewResource;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Unit tests for the package's attribute provider of preview resources, which
 * offers policies what a preview names, under `resource`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PreviewAttributes::class)]
final class PreviewAttributesTest extends TestCase
{
    /**
     * It declares the target, the identity and the application, each a string.
     *
     * @return void
     */
    public function testDeclaresWhatAPreviewNames(): void
    {
        $provider = new PreviewAttributes;

        self::assertInstanceOf(ResourceAttributeProvider::class, $provider);
        self::assertSame([
            'target_type'   => ContextKeyType::STRING,
            'target_id'     => ContextKeyType::STRING,
            'identity_type' => ContextKeyType::STRING,
            'identity_id'   => ContextKeyType::STRING,
            'application'   => ContextKeyType::STRING,
        ], $provider->attributes());
    }

    /**
     * A preview resource's reference gets its attributes; any other resource of
     * the type, or of another, gets none.
     *
     * @return void
     */
    public function testValuesAreThoseOfAPreviewResourceAlone(): void
    {
        $provider = new PreviewAttributes;
        $preview  = new PreviewResource(new Reference('user', '42'), null, null, 'admin');

        self::assertSame(['target_type' => 'user', 'target_id' => '42', 'application' => 'admin'], $provider->values($preview->toResourceReference(), null));
        self::assertSame([], $provider->values(ResourceReference::record(PreviewResource::TYPE, 'user:42'), null));
        self::assertSame([], $provider->values(ResourceReference::record('post', '1'), null));
    }
}
