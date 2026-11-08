<?php

declare(strict_types = 1);

namespace Tests\Unit\Preview;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Preview\PreviewResource;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the resource a preview's admission is decided on: the target
 * and the scope, as references and names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PreviewResource::class)]
final class PreviewResourceTest extends TestCase
{
    /**
     * Its reference is a record of the preview type keyed by the principal
     * previewed, in the preview's tenant, handing the resource on.
     *
     * @return void
     */
    public function testItsReferenceNamesThePrincipalInThePreviewsTenant(): void
    {
        $tenant   = new Reference('tenant', 't1');
        $preview  = new PreviewResource(new Reference('user', '42'), new Reference('person', '7'), $tenant, 'admin');
        $resource = $preview->toResourceReference();

        self::assertInstanceOf(AuthorizableResource::class, $preview);
        self::assertSame('authorization:preview', PreviewResource::TYPE);
        self::assertSame('authorization:preview:user:42', $resource->identifier);
        self::assertSame('authorization:preview', $resource->type);
        self::assertSame('user:42', $resource->id);
        self::assertSame($tenant, $resource->tenant);
        self::assertNull($resource->model);
        self::assertSame($preview, $resource->source);
        self::assertNull((new PreviewResource(new Reference('user', '42'), null, null, null))->toResourceReference()->tenant);
    }

    /**
     * Its attributes name the principal, the identity and the application, and
     * leave out what it has none of.
     *
     * @return void
     */
    public function testItsAttributesNameTheTargetAndTheApplication(): void
    {
        $full = new PreviewResource(new Reference('user', '42'), new Reference('person', '7'), new Reference('tenant', 't1'), 'admin');
        $bare = new PreviewResource(new Reference('user', '42'), null, null, null);

        self::assertSame(['target_type' => 'user', 'target_id' => '42', 'identity_type' => 'person', 'identity_id' => '7', 'application' => 'admin'], $full->attributes());
        self::assertSame(['target_type' => 'user', 'target_id' => '42'], $bare->attributes());
    }
}
