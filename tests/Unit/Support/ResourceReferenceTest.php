<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Unit tests for `ResourceReference`, the resource a check is about: its type,
 * id, tenant and the identifier statements match against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ResourceReference::class)]
final class ResourceReferenceTest extends TestCase
{
    /**
     * An identifier given alone is opaque: used as given, with no type, id or
     * tenant.
     *
     * @return void
     */
    public function testAnIdentifierAloneIsOpaque(): void
    {
        $reference = new ResourceReference('report:9');

        self::assertSame('report:9', $reference->identifier);
        self::assertNull($reference->type);
        self::assertNull($reference->id);
        self::assertNull($reference->tenant);
    }

    /**
     * Every part of a reference is kept as given to the constructor.
     *
     * @return void
     */
    public function testKeepsEveryPartGiven(): void
    {
        $tenant    = new Reference('stub_tenant', '7');
        $reference = new ResourceReference('custom', 'post', '42', $tenant);

        self::assertSame('custom', $reference->identifier);
        self::assertSame('post', $reference->type);
        self::assertSame('42', $reference->id);
        self::assertSame($tenant, $reference->tenant);
    }

    /**
     * A record is identified as `type:id`, with no tenant unless one is given.
     *
     * @return void
     */
    public function testARecordIsIdentifiedByItsTypeAndId(): void
    {
        $tenant = new Reference('stub_tenant', '7');
        $record = ResourceReference::record('post', '42');

        self::assertSame('post:42', $record->identifier);
        self::assertSame('post', $record->type);
        self::assertSame('42', $record->id);
        self::assertNull($record->tenant);
        self::assertSame($tenant, ResourceReference::record('post', '42', $tenant)->tenant);
    }

    /**
     * A type alone is identified as `type:*`, with no id, so a pattern naming
     * the type covers it and one naming a single record does not.
     *
     * @return void
     */
    public function testATypeAloneIsIdentifiedByItsTypeAndAWildcard(): void
    {
        $tenant = new Reference('stub_tenant', '7');
        $type   = ResourceReference::type('post');

        self::assertSame('post:*', $type->identifier);
        self::assertSame('post', $type->type);
        self::assertNull($type->id);
        self::assertNull($type->tenant);
        self::assertSame($tenant, ResourceReference::type('post', $tenant)->tenant);
    }

    /**
     * A reference cannot be changed once made.
     *
     * @return void
     */
    public function testIsReadOnly(): void
    {
        self::assertTrue((new \ReflectionClass(ResourceReference::class))->isReadOnly());
    }
}
