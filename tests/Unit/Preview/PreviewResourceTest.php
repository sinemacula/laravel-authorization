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

    /**
     * A preview is put in another scope keeping its target: the tenant, the
     * application and whether it is decided just below the tenant are the ones
     * given, and a preview is decided in its tenant unless told.
     *
     * @return void
     */
    public function testAPreviewIsPutInAnotherScopeKeepingItsTarget(): void
    {
        $target   = new Reference('user', '42');
        $identity = new Reference('person', '7');
        $tenant   = new Reference('tenant', 't2');
        $preview  = new PreviewResource($target, $identity, new Reference('tenant', 't1'), 'admin');
        $below    = $preview->in($tenant, 'billing', true);

        self::assertFalse($preview->isBelow);
        self::assertSame([$target, $identity, $tenant, 'billing', true], [$below->target, $below->identity, $below->tenant, $below->application, $below->isBelow]);
        self::assertFalse($preview->in(null, null, false)->isBelow);
        self::assertNull($preview->in(null, null, false)->tenant);
    }
}
