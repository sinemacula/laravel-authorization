<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\PermissionMetadataReader;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\Feature\Stubs\Enums\EmptyGuardsPermission;
use Tests\Feature\Stubs\Enums\IntBackedPermissionEnum;
use Tests\Feature\Stubs\Enums\InvalidGuardsPermission;
use Tests\Feature\Stubs\Enums\UnreadableAttributePermission;

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

    /**
     * Provide each case listing an invalid guard, with how the reason describes
     * that guard.
     *
     * @return iterable<string, array{\Tests\Feature\Stubs\Enums\InvalidGuardsPermission, string}>
     */
    public static function invalidGuardProvider(): iterable
    {
        yield 'null' => [InvalidGuardsPermission::NULL_GUARD, 'null'];

        yield 'integer' => [InvalidGuardsPermission::INTEGER_GUARD, 'int'];

        yield 'empty string' => [InvalidGuardsPermission::EMPTY_GUARD, 'an empty string'];
    }

    /**
     * A guard that is not a non-empty string is refused, naming the case, even
     * beside a valid guard.
     *
     * @param  \Tests\Feature\Stubs\Enums\InvalidGuardsPermission  $case
     * @param  string  $got
     * @return void
     */
    #[DataProvider('invalidGuardProvider')]
    public function testAGuardThatIsNotANonEmptyStringIsRefused(InvalidGuardsPermission $case, string $got): void
    {
        self::assertRefused(
            $case,
            InvalidGuardsPermission::class . '::' . $case->name,
            "every guard must be a non-empty string, got {$got}; leave the list out for a guard-agnostic permission.",
        );
    }

    /**
     * A repeated attribute cannot be instantiated, so it is refused, naming the
     * case, rather than failing with the raw error.
     *
     * @return void
     */
    public function testARepeatedAttributeIsRefused(): void
    {
        self::assertRefused(
            UnreadableAttributePermission::REPEATED,
            UnreadableAttributePermission::class . '::REPEATED',
            'the #[Permission] attribute cannot be read: Attribute "' . PermissionMeta::class . '" must not be repeated',
        );
    }

    /**
     * An attribute given an argument of the wrong type cannot be instantiated,
     * so it is refused, naming the case, rather than failing with a TypeError.
     *
     * @return void
     */
    public function testAnAttributeWithAWrongTypedArgumentIsRefused(): void
    {
        try {
            (new PermissionMetadataReader)->read(UnreadableAttributePermission::WRONG_TYPE);
            self::fail('InvalidPermissionCatalogueException was not thrown.');
        } catch (InvalidPermissionCatalogueException $exception) {
            self::assertSame(UnreadableAttributePermission::class . '::WRONG_TYPE', $exception->getSource());
            self::assertStringStartsWith(
                'the #[Permission] attribute cannot be read: ' . PermissionMeta::class . '::__construct(): Argument #1 ($description) must be of type ?string, int given',
                $exception->getReason(),
            );
        }
    }

    /**
     * A case of an enum not backed by strings names no permission, so it is
     * refused, naming the case, rather than failing with a TypeError.
     *
     * @return void
     */
    public function testACaseNotBackedByAStringIsRefused(): void
    {
        self::assertRefused(
            IntBackedPermissionEnum::POSTS_CREATE,
            IntBackedPermissionEnum::class . '::POSTS_CREATE',
            'the enum must be backed by strings, since each case\'s value is a permission name.',
        );
    }

    /**
     * Assert that reading the definitions of the given case is refused with the
     * given source and reason.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PermissionEnum  $case
     * @param  string  $source
     * @param  string  $reason
     * @return void
     */
    private static function assertRefused(PermissionEnum $case, string $source, string $reason): void
    {
        try {
            (new PermissionMetadataReader)->definitions($case);
            self::fail('InvalidPermissionCatalogueException was not thrown.');
        } catch (InvalidPermissionCatalogueException $exception) {
            self::assertSame($source, $exception->getSource());
            self::assertSame($reason, $exception->getReason());
        }
    }
}
