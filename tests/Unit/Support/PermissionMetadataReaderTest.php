<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\PermissionMetadataReader;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\Feature\Stubs\Enums\EmptyGuardsPermission;

/**
 * Unit tests for `PermissionMetadataReader`, which reads a permission enum
 * case's `#[Permission]` attribute and turns the case into definitions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PermissionMetadataReader::class)]
#[CoversClass(PermissionMeta::class)]
#[CoversClass(PermissionDefinition::class)]
final class PermissionMetadataReaderTest extends TestCase
{
    /**
     * The attribute on a case is read as declared.
     *
     * @return void
     */
    public function testReadsTheAttributeOnTheCase(): void
    {
        $metadata = (new PermissionMetadataReader)->read(CataloguePermission::POSTS_PUBLISH);

        self::assertSame('Publish posts', $metadata->description);
        self::assertSame('Posts', $metadata->category);
        self::assertSame(['web', 'api'], $metadata->guards);
    }

    /**
     * A case without the attribute reads as one with every field null.
     *
     * @return void
     */
    public function testReadsACaseWithoutTheAttributeAsAllNull(): void
    {
        $metadata = (new PermissionMetadataReader)->read(CataloguePermission::POSTS_ARCHIVE);

        self::assertNull($metadata->description);
        self::assertNull($metadata->category);
        self::assertNull($metadata->guards);
    }

    /**
     * A case whose attribute lists no guards declares one guard-agnostic
     * permission named by the case's value, with the attribute's metadata.
     *
     * @return void
     */
    public function testACaseWithoutGuardsDeclaresOneGuardAgnosticPermission(): void
    {
        self::assertEquals(
            [new PermissionDefinition(name: 'posts:create', description: 'Create posts', category: 'Posts')],
            (new PermissionMetadataReader)->definitions(CataloguePermission::POSTS_CREATE),
        );
    }

    /**
     * A case whose attribute lists guards declares one permission per guard, in
     * the order listed.
     *
     * @return void
     */
    public function testACaseWithGuardsDeclaresOnePermissionPerGuard(): void
    {
        self::assertEquals(
            [
                new PermissionDefinition(name: 'posts.publish', description: 'Publish posts', category: 'Posts', guard: 'web'),
                new PermissionDefinition(name: 'posts.publish', description: 'Publish posts', category: 'Posts', guard: 'api'),
            ],
            (new PermissionMetadataReader)->definitions(CataloguePermission::POSTS_PUBLISH),
        );
    }

    /**
     * A case without the attribute declares one guard-agnostic permission with
     * no metadata.
     *
     * @return void
     */
    public function testACaseWithoutTheAttributeDeclaresOneBarePermission(): void
    {
        self::assertEquals(
            [new PermissionDefinition('posts:archive')],
            (new PermissionMetadataReader)->definitions(CataloguePermission::POSTS_ARCHIVE),
        );
    }

    /**
     * An empty guard list declares nothing and is refused, naming the case.
     *
     * @return void
     */
    public function testAnEmptyGuardListIsRefused(): void
    {
        try {
            (new PermissionMetadataReader)->definitions(EmptyGuardsPermission::REPORTS_EXPORT);
            self::fail('InvalidPermissionCatalogueException was not thrown.');
        } catch (InvalidPermissionCatalogueException $exception) {
            self::assertSame(EmptyGuardsPermission::class . '::REPORTS_EXPORT', $exception->getSource());
            self::assertSame('the guard list is empty; leave it out for a guard-agnostic permission.', $exception->getReason());
        }
    }
}
