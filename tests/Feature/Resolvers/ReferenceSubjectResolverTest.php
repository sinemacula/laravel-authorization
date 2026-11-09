<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException;
use SineMacula\Laravel\Authorization\Resolvers\ReferenceSubjectResolver;
use Tests\Feature\Stubs\FailingSubjectResolver;
use Tests\Feature\Stubs\NumberedIdentity;
use Tests\Feature\Stubs\PlainIdentity;
use Tests\Feature\Stubs\PrincipalSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the default console subject resolver: the saved model a
 * `{morphType}:{key}` reference names, mapped to its principal and identity by
 * the bound subject resolver, with no tenant, application or session, and every
 * reference it cannot resolve refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ReferenceSubjectResolver::class)]
final class ReferenceSubjectResolverTest extends TestCase
{
    /** @var string A value a failure holds, which no refusal may carry. */
    private const string SECRET = 'sentinel-failure-8a41';

    /**
     * Clear the morph map a test sets.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * The package binds it as the console subject resolver.
     *
     * @return void
     */
    public function testIsTheBoundConsoleSubjectResolver(): void
    {
        self::assertInstanceOf(ReferenceSubjectResolver::class, $this->app?->make(ConsoleSubjectResolver::class));
    }

    /**
     * Under the shipped subject resolver, the model named by its class is its
     * own principal and identity, with the guard kept and no tenant,
     * application or session.
     *
     * @return void
     */
    public function testAModelIsItsOwnPrincipalAndIdentity(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $subject = $this->resolver()->resolve(StubIdentity::class . ':user-1');

        self::assertTrue($user->is(self::model($subject->subject)));
        self::assertSame($subject->subject, $subject->identity);
        self::assertNull($subject->tenant);
        self::assertNull($subject->application);
        self::assertSame('web', $subject->guard);
        self::assertNull($subject->session);
    }

    /**
     * A morph alias resolves to the model it maps to.
     *
     * @return void
     */
    public function testAMorphAliasNamesItsModel(): void
    {
        Relation::morphMap(['person' => StubIdentity::class]);

        $user    = StubIdentity::create(['id' => 'user-2']);
        $subject = $this->resolver()->resolve('person:user-2');

        self::assertTrue($user->is(self::model($subject->subject)));
    }

    /**
     * Under a subject resolver with principals, a person named is mapped to the
     * principal it acts as, with itself as the identity, and naming the
     * principal keeps the identity behind it; either way the request's tenant,
     * application and session are dropped while the guard is kept.
     *
     * @return void
     */
    public function testAPersonIsMappedToThePrincipalItActsAs(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-1']);
        $person    = StubSecondIdentity::create(['id' => 'person-1']);
        $tenant    = StubTenant::query()->create(['id' => 'tenant-1', 'name' => 'tenant-1']);

        $this->app?->instance(SubjectResolver::class, new PrincipalSubjectResolver($principal, $person, $tenant));

        foreach ([StubSecondIdentity::class . ':person-1', StubIdentity::class . ':principal-1'] as $reference) {
            $subject = $this->resolver()->resolve($reference);

            self::assertSame($principal, $subject->subject, $reference);
            self::assertSame($person, $subject->identity, $reference);
            self::assertNull($subject->tenant, $reference);
            self::assertNull($subject->application, $reference);
            self::assertSame('web', $subject->guard, $reference);
            self::assertNull($subject->session, $reference);
        }
    }

    /**
     * The subject resolver is read on every call, so one bound after the
     * console resolver was built is honoured.
     *
     * @return void
     */
    public function testReadsTheBoundSubjectResolverOnEveryCall(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-2']);
        $person    = StubSecondIdentity::create(['id' => 'person-2']);
        $resolver  = $this->resolver();

        self::assertTrue($person->is(self::model($resolver->resolve(StubSecondIdentity::class . ':person-2')->subject)));

        $this->app?->instance(SubjectResolver::class, new PrincipalSubjectResolver($principal, $person));

        self::assertSame($principal, $resolver->resolve(StubSecondIdentity::class . ':person-2')->subject);
    }

    /**
     * Return the malformed references.
     *
     * @return iterable<string, array{string}>
     */
    public static function malformedReferences(): iterable
    {
        yield 'empty' => [''];
        yield 'no key' => ['user'];
        yield 'empty type' => [':1'];
        yield 'empty key' => ['user:'];
    }

    /**
     * A reference not in the `{morphType}:{key}` format is refused.
     *
     * @param  string  $reference
     * @return void
     */
    #[DataProvider('malformedReferences')]
    public function testRefusesAMalformedReference(string $reference): void
    {
        $this->assertRefused($reference, 'The subject must be in the format {morphType}:{key} (e.g. user:1).');
    }

    /**
     * A type that names no Eloquent model, through the morph map or as a class
     * name, is refused, naming the type.
     *
     * @return void
     */
    public function testRefusesATypeThatNamesNoModel(): void
    {
        $this->assertRefused('nothing:1', 'The subject type \'nothing\' is not an Eloquent model.');
        $this->assertRefused(\stdClass::class . ':1', 'The subject type \'stdClass\' is not an Eloquent model.');
    }

    /**
     * A key no row has is refused, naming the reference.
     *
     * @return void
     */
    public function testRefusesAnUnknownSubject(): void
    {
        $reference = StubIdentity::class . ':missing';

        $this->assertRefused($reference, "No subject '{$reference}' was found.");
    }

    /**
     * A model whose principal is no authorizable identity, or no saved one,
     * cannot be checked and is refused.
     *
     * @return void
     */
    public function testRefusesAModelThatCannotBeChecked(): void
    {
        StubTenant::query()->create(['id' => 'tenant-2', 'name' => 'tenant-2']);

        $tenant = StubTenant::class . ':tenant-2';

        $this->assertRefused($tenant, "The subject '{$tenant}' cannot be checked: its principal is not a saved authorizable identity.");

        $person = StubSecondIdentity::create(['id' => 'person-3']);

        $this->app?->instance(SubjectResolver::class, new PrincipalSubjectResolver(new StubIdentity(['id' => 'unsaved']), $person));

        $reference = StubSecondIdentity::class . ':person-3';

        $this->assertRefused($reference, "The subject '{$reference}' cannot be checked: its principal is not a saved authorizable identity.");

        foreach ([new PlainIdentity, new \stdClass] as $principal) {
            $this->app?->instance(SubjectResolver::class, new PrincipalSubjectResolver($principal, $person));

            $this->assertRefused($reference, "The subject '{$reference}' cannot be checked: its principal is not a saved authorizable identity.");
        }
    }

    /**
     * A key may hold a colon: only the first one ends the type.
     *
     * @return void
     */
    public function testAKeyMayHoldAColon(): void
    {
        $user = StubIdentity::create(['id' => 'org:7']);

        self::assertTrue($user->is(self::model($this->resolver()->resolve(StubIdentity::class . ':org:7')->subject)));
    }

    /**
     * A lookup that fails is refused without naming the reference or the
     * failure, which is kept as the previous exception.
     *
     * @return void
     */
    public function testRefusesALookupThatFails(): void
    {
        StubIdentity::create(['id' => 'user-2']);

        StubIdentity::retrieved(static function (): never {
            throw new \RuntimeException(self::SECRET);
        });

        $exception = $this->refusal(StubIdentity::class . ':user-2', 'The subject could not be resolved.');

        self::assertInstanceOf(\RuntimeException::class, $exception->getPrevious());
        self::assertSame(self::SECRET, $exception->getPrevious()->getMessage());
    }

    /**
     * A key the key column cannot hold is refused as not found or, on a
     * database that refuses to compare it, as unresolvable, never with the
     * database's error.
     *
     * @return void
     */
    public function testRefusesAKeyTheKeyColumnCannotHold(): void
    {
        $reference = NumberedIdentity::class . ':abc';

        try {
            $this->resolver()->resolve($reference);

            self::fail("The reference '{$reference}' is refused.");
        } catch (UnresolvedSubjectException $exception) {
            self::assertContains($exception->getMessage(), ["No subject '{$reference}' was found.", 'The subject could not be resolved.']);
        }
    }

    /**
     * A subject resolver that fails, with any exception, is refused without
     * naming the failure, which is kept as the previous exception.
     *
     * @return void
     */
    public function testRefusesASubjectResolverThatFails(): void
    {
        StubIdentity::create(['id' => 'user-3']);

        foreach ([new \RuntimeException(self::SECRET), new \InvalidArgumentException(self::SECRET)] as $failure) {
            $this->app?->instance(SubjectResolver::class, new FailingSubjectResolver($failure));

            $exception = $this->refusal(StubIdentity::class . ':user-3', 'The subject could not be resolved.');

            self::assertSame($failure, $exception->getPrevious());
        }
    }

    /**
     * A model the subject resolver maps to a subject that is not about it,
     * neither as its principal nor as its identity, is ambiguous and refused.
     *
     * @return void
     */
    public function testRefusesAModelMappedToAnotherSubject(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-3']);
        $person    = StubSecondIdentity::create(['id' => 'person-4']);

        StubIdentity::create(['id' => 'stranger-1']);

        $this->app?->instance(SubjectResolver::class, new PrincipalSubjectResolver($principal, $person));

        $reference = StubIdentity::class . ':stranger-1';

        $this->assertRefused($reference, "The subject '{$reference}' is ambiguous: the subject resolver maps it to a subject that is not about it.");
    }

    /**
     * A copy of the model named, the same row loaded again, is the model named.
     *
     * @return void
     */
    public function testAReloadedModelIsTheModelNamed(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-4']);

        StubSecondIdentity::create(['id' => 'person-5']);

        $this->app?->instance(SubjectResolver::class, new PrincipalSubjectResolver($principal, StubSecondIdentity::query()->findOrFail('person-5')));

        self::assertSame($principal, $this->resolver()->resolve(StubSecondIdentity::class . ':person-5')->subject);
    }

    /**
     * Assert the reference is refused with the message.
     *
     * @param  string  $reference
     * @param  string  $message
     * @return void
     */
    private function assertRefused(string $reference, string $message): void
    {
        $this->refusal($reference, $message);
    }

    /**
     * Assert the reference is refused with the message, and return the refusal.
     *
     * @param  string  $reference
     * @param  string  $message
     * @return \SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException
     */
    private function refusal(string $reference, string $message): UnresolvedSubjectException
    {
        try {
            $this->resolver()->resolve($reference);
        } catch (UnresolvedSubjectException $exception) {
            self::assertSame($message, $exception->getMessage());

            return $exception;
        }

        self::fail("The reference '{$reference}' is refused.");
    }

    /**
     * Return a console subject resolver reading the test's container.
     *
     * @return \SineMacula\Laravel\Authorization\Resolvers\ReferenceSubjectResolver
     */
    private function resolver(): ReferenceSubjectResolver
    {
        self::assertNotNull($this->app);

        return new ReferenceSubjectResolver($this->app);
    }

    /**
     * Return the subject's principal as the model it is.
     *
     * @param  object  $principal
     * @return \Tests\Feature\Stubs\StubIdentity|\Tests\Feature\Stubs\StubSecondIdentity
     */
    private static function model(object $principal): StubIdentity|StubSecondIdentity
    {
        self::assertTrue($principal instanceof StubIdentity || $principal instanceof StubSecondIdentity);

        return $principal;
    }
}
