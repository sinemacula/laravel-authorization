<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\GuardUserIdentityDirectory;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\TestCase;

/**
 * Feature tests for the default identity directory.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardUserIdentityDirectory::class)]
final class GuardUserIdentityDirectoryTest extends TestCase
{
    /**
     * Under the shipped subject resolver every user is its own identity, so an
     * identity owns no other principal and the list is complete; nothing is
     * read from the identity's model to say so.
     *
     * @return void
     */
    public function testTheShippedResolversUserOwnsNoOtherPrincipal(): void
    {
        self::assertInstanceOf(AuthGuardSubjectResolver::class, $this->app?->make(SubjectResolver::class));

        foreach ([Reference::of(StubIdentity::create(['id' => 'user'])), new Reference('anything', 'missing')] as $identity) {
            $principals = self::directory()->principalsOf($identity);

            self::assertSame([], $principals->principals);
            self::assertTrue($principals->isComplete);
        }
    }

    /**
     * Under any other resolver the package cannot know an identity's
     * principals, so the list is incomplete; the resolver bound when asked is
     * the one read.
     *
     * @return void
     */
    public function testAnotherResolversPrincipalsAreUnknown(): void
    {
        $directory = self::directory();

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver);

        $principals = $directory->principalsOf(Reference::of(StubIdentity::create(['id' => 'user'])));

        self::assertSame([], $principals->principals);
        self::assertFalse($principals->isComplete);
    }

    /**
     * Return the identity directory the container builds by default.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory
     */
    private static function directory(): IdentityDirectory
    {
        $directory = app(IdentityDirectory::class);

        self::assertInstanceOf(GuardUserIdentityDirectory::class, $directory);

        return $directory;
    }
}
