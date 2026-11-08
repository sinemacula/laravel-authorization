<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\ScopedPost;

/**
 * Unit tests for the provenance of a decision: who it was about, who previewed
 * it, and where it was made, as references alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionProvenance::class)]
final class DecisionProvenanceTest extends TestCase
{
    /**
     * Forget any container a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance(null);

        parent::tearDown();
    }

    /**
     * A provenance holds what it is given, and none of it by default.
     *
     * @return void
     */
    public function testHoldsWhatItIsGiven(): void
    {
        $subject   = new Reference('user', '1');
        $identity  = new Reference('identity', '2');
        $previewer = new Reference('user', '3');
        $tenant    = new Reference('tenant', '4');

        $provenance = new DecisionProvenance($subject, $identity, $previewer, $tenant, 'admin');

        self::assertSame($subject, $provenance->subject);
        self::assertSame($identity, $provenance->identity);
        self::assertSame($previewer, $provenance->previewer);
        self::assertSame($tenant, $provenance->tenant);
        self::assertSame('admin', $provenance->application);
        self::assertEquals(new DecisionProvenance(null, null, null, null, null), new DecisionProvenance);
    }

    /**
     * The provenance of a decision about a subject names its principal and its
     * identity by reference, and no previewer unless one is given; outside any
     * scope it names no tenant or application, never reading the subject's.
     *
     * @return void
     */
    public function testNamesTheSubjectByReference(): void
    {
        $principal = self::identity(StubIdentity::class, 'user-1');
        $identity  = self::identity(StubSecondIdentity::class, 'person-1');
        $tenant    = (new StubTenant)->forceFill(['id' => 'tenant-1']);
        $subject   = new Subject($principal, $identity, $tenant, 'admin', 'web', 'session-1');

        $provenance = DecisionProvenance::of($subject);

        self::assertEquals(new Reference($principal->getMorphClass(), 'user-1'), $provenance->subject);
        self::assertEquals(new Reference($identity->getMorphClass(), 'person-1'), $provenance->identity);
        self::assertNull($provenance->tenant);
        self::assertNull($provenance->application);
        self::assertNull($provenance->previewer);
        self::assertFalse($provenance->isPreview());

        $previewer = new Reference('user', 'admin-1');
        $preview   = DecisionProvenance::of($subject, $previewer);

        self::assertSame($previewer, $preview->previewer);
        self::assertTrue($preview->isPreview());
        self::assertEquals($provenance->subject, $preview->subject);
    }

    /**
     * The tenant and the application are those of the scope in place, not the
     * subject's, a guest's decision included.
     *
     * @return void
     */
    public function testNamesTheScopeInPlace(): void
    {
        $this->container();

        $principal = self::identity(StubIdentity::class, 'user-1');
        $subject   = new Subject($principal, null, (new StubTenant)->forceFill(['id' => 'tenant-1']), 'web');
        $scope     = (new StubTenant)->forceFill(['id' => 'tenant-2']);
        $where     = new Reference($scope->getMorphClass(), 'tenant-2');

        [$about, $guest] = TenantScope::within($scope, 'admin', static fn (): array => [DecisionProvenance::of($subject), DecisionProvenance::of(null)]);

        self::assertEquals(new DecisionProvenance(new Reference($principal->getMorphClass(), 'user-1'), null, null, $where, 'admin'), $about);
        self::assertEquals(new DecisionProvenance(null, null, null, $where, 'admin'), $guest);
        self::assertEquals(new DecisionProvenance(application: 'admin'), TenantScope::within(null, 'admin', static fn (): DecisionProvenance => DecisionProvenance::of(null)));
    }

    /**
     * The provenance made in the scope in place keeps who the decision was
     * about and who previewed it, and names the scope in place now.
     *
     * @return void
     */
    public function testInTheCurrentScopeKeepsWhoItWasAbout(): void
    {
        $this->container();

        $subject   = new Reference('user', '1');
        $identity  = new Reference('identity', '2');
        $previewer = new Reference('user', '3');
        $scope     = (new StubTenant)->forceFill(['id' => 'tenant-2']);
        $made      = new DecisionProvenance($subject, $identity, $previewer, new Reference('tenant', '4'), 'web');

        $provenance = TenantScope::within($scope, 'admin', static fn (): DecisionProvenance => $made->inCurrentScope());

        self::assertEquals(new DecisionProvenance($subject, $identity, $previewer, new Reference($scope->getMorphClass(), 'tenant-2'), 'admin'), $provenance);
        self::assertEquals(new DecisionProvenance($subject, $identity, $previewer), $made->inCurrentScope());
    }

    /**
     * A tenant in place that cannot be read is named as none, the application
     * still named.
     *
     * @return void
     */
    public function testNamesNoTenantThatCannotBeRead(): void
    {
        $this->container();

        $provenance = TenantScope::within(new StubTenant, 'admin', static fn (): DecisionProvenance => DecisionProvenance::of(null));

        self::assertEquals(new DecisionProvenance(application: 'admin'), $provenance);
    }

    /**
     * A record whose key is an integer is named by its key as text.
     *
     * @return void
     */
    public function testNamesARecordWithAnIntegerKeyByItsKeyAsText(): void
    {
        $record = (new ScopedPost)->forceFill(['id' => 7]);

        self::assertSame(7, $record->getKey());
        self::assertEquals(new Reference($record->getMorphClass(), '7'), DecisionProvenance::of(new Subject($record))->subject);
    }

    /**
     * A record that is no model or tenant, or a model with no key, is named by
     * no reference, so nothing that is not a saved record is ever named.
     *
     * @return void
     */
    public function testNamesNoRecordWithoutAKey(): void
    {
        $unsaved    = new StubIdentity;
        $provenance = DecisionProvenance::of(new Subject($unsaved, new \stdClass, self::identity(StubIdentity::class, '')));

        self::assertNull($provenance->subject);
        self::assertNull($provenance->identity);
        self::assertNull(DecisionProvenance::of(new Subject(self::identity(StubIdentity::class, ''), $unsaved))->subject);
    }

    /**
     * Make a container that resolves the request about no one under the `web`
     * guard, so a scope can be put in place.
     *
     * @return void
     */
    private function container(): void
    {
        $container = new Container;

        $container->instance('config', new Repository(['auth' => ['defaults' => ['guard' => 'web']]]));
        $container->instance(SubjectResolver::class, new StubSubjectResolver);

        Container::setInstance($container);
    }

    /**
     * Return a model of the class with the key given, unsaved.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  class-string<TModel>  $class
     * @param  string  $key
     * @return TModel
     */
    private static function identity(string $class, string $key): object
    {
        return (new $class)->forceFill(['id' => $key]);
    }
}
