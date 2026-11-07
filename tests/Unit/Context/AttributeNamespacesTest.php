<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Context\AttributeNamespaces;
use SineMacula\Laravel\Authorization\Context\AttributeProviders;
use SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\Feature\Stubs\RecordingSubjectAttributes;
use Tests\Fixtures\BulkChecks\FixedBulkAttributes;
use Tests\Fixtures\QueryScoping\InvariantSubjectAttributes;

/**
 * Unit tests for `AttributeNamespaces`, which builds the `subject` and
 * `resource` namespaces of a check from their built-in keys and providers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AttributeNamespaces::class)]
final class AttributeNamespacesTest extends TestCase
{
    /**
     * A check with no subject and no resource has neither namespace.
     *
     * @return void
     */
    public function testNoSubjectOrResourceHasNoNamespace(): void
    {
        self::assertSame([], (new AttributeNamespaces)->builders(null, null));
        self::assertSame([false, null], self::context(null, null)->lookup('subject.id'));
        self::assertSame([false, null], self::context(null, null)->lookup('resource.type'));
    }

    /**
     * A record has its id, its type and its tenant's type and id.
     *
     * @return void
     */
    public function testARecordHasItsIdTypeAndTenant(): void
    {
        $context = self::context(null, ResourceReference::record('post', '42', new Reference('team', 't-1')));

        self::assertSame([true, ['id' => '42', 'type' => 'post', 'tenant' => ['type' => 'team', 'id' => 't-1']]], $context->lookup('resource'));
        self::assertSame([false, null], $context->lookup('subject'));
    }

    /**
     * A type alone has its type and no id, and a resource with no tenant no
     * tenant keys.
     *
     * @return void
     */
    public function testATypeAloneHasItsTypeOnly(): void
    {
        $context = self::context(null, ResourceReference::type('post'));

        self::assertSame([true, ['type' => 'post']], $context->lookup('resource'));
        self::assertSame([false, null], $context->lookup('resource.id'));
        self::assertSame([false, null], $context->lookup('resource.tenant.id'));
    }

    /**
     * An opaque identifier has neither id nor type, never read by splitting it,
     * so the namespace is absent; one given a tenant has that alone.
     *
     * @return void
     */
    public function testAnOpaqueIdentifierHasNeitherIdNorType(): void
    {
        self::assertSame([false, null], self::context(null, new ResourceReference('post:42'))->lookup('resource'));
        self::assertSame(
            [true, ['tenant' => ['type' => 'team', 'id' => 't-1']]],
            self::context(null, new ResourceReference('post:42', tenant: new Reference('team', 't-1')))->lookup('resource'),
        );
    }

    /**
     * A model subject has its key and morph class, and its tenant's type and id
     * when it has a tenant.
     *
     * @return void
     */
    public function testAModelSubjectHasItsKeyTypeAndTenant(): void
    {
        $user = new class extends Model {};

        $user->setRawAttributes(['id' => 7]);

        $context = self::context(new Subject($user, $user, new Reference('team', 't-1')), null);

        self::assertSame([true, ['id' => '7', 'type' => $user->getMorphClass(), 'tenant' => ['type' => 'team', 'id' => 't-1']]], $context->lookup('subject'));
        self::assertSame([false, null], self::context(new Subject($user), null)->lookup('subject.tenant'));
        self::assertSame([true, '7'], self::context(new Subject($user), null)->lookup('subject.id'));
    }

    /**
     * A subject with no usable key has no id, and one with no morph class is
     * typed by its class name.
     *
     * @return void
     */
    public function testASubjectWithoutAKeyOrMorphClass(): void
    {
        $unsaved = new class extends Model {};

        self::assertSame([true, ['type' => $unsaved->getMorphClass()]], self::context(new Subject($unsaved), null)->lookup('subject'));
        self::assertSame([true, ['type' => \stdClass::class]], self::context(new Subject(new \stdClass), null)->lookup('subject'));
        self::assertSame([true, ['id' => 'abc', 'type' => 'robot']], self::context(new Subject(self::keyed('abc', 'robot')), null)->lookup('subject'));
        self::assertSame([true, ['type' => 'robot']], self::context(new Subject(self::keyed('', 'robot')), null)->lookup('subject'));
        self::assertSame([true, ['type' => 'robot']], self::context(new Subject(self::keyed(1.5, 'robot')), null)->lookup('subject'));
        self::assertSame([true, ['id' => '3', 'type' => 'robot']], self::context(new Subject(self::keyed(3, 'robot')), null)->lookup('subject'));
        self::assertSame(
            [true, ['type' => self::keyed(3, '')::class]],
            self::context(new Subject(self::keyed(null, '')), null)->lookup('subject'),
        );
    }

    /**
     * A subject's tenant that is not one fails as `TenantScope` refuses it.
     *
     * @return void
     */
    public function testASubjectsInvalidTenantIsRefused(): void
    {
        $this->expectException(InvalidTenantException::class);

        self::context(new Subject(new \stdClass, null, new \stdClass), null)->lookup('subject.id');
    }

    /**
     * The providers' declared attributes join the built-ins, which they never
     * replace, and only a record is given to its type's provider.
     *
     * @return void
     */
    public function testProvidersAttributesJoinTheBuiltIns(): void
    {
        $container = new Container;
        $posts     = new RecordingResourceAttributes;
        $users     = new RecordingSubjectAttributes;

        $container->instance(RecordingResourceAttributes::class, $posts);
        $container->instance(RecordingSubjectAttributes::class, $users);

        $namespaces = new AttributeNamespaces(new AttributeProviders(
            $container,
            ['post' => RecordingResourceAttributes::class],
            [\stdClass::class => RecordingSubjectAttributes::class],
        ));
        $subject = new \stdClass;
        $context = new CheckContext([], $namespaces->builders(new Subject($subject), ResourceReference::record('post', '42')));

        self::assertSame([true, ['id' => '42', 'type' => 'post', 'status' => 'draft', 'owner' => ['id' => '7']]], $context->lookup('resource'));
        self::assertSame([true, ['type' => \stdClass::class, 'department' => 'sales']], $context->lookup('subject'));
        self::assertSame([$subject], $users->calls);

        $typeAlone = new CheckContext([], $namespaces->builders(null, ResourceReference::type('post')));

        self::assertSame([true, ['type' => 'post']], $typeAlone->lookup('resource'));
        self::assertCount(1, $posts->calls);
    }

    /**
     * Neither namespace is built until it is read.
     *
     * @return void
     */
    public function testNeitherNamespaceIsBuiltUntilRead(): void
    {
        $container = new Container;
        $posts     = new RecordingResourceAttributes;

        $container->instance(RecordingResourceAttributes::class, $posts);

        $builders = (new AttributeNamespaces(new AttributeProviders($container, ['post' => RecordingResourceAttributes::class])))
            ->builders(new Subject(new \stdClass), ResourceReference::record('post', '1'));

        self::assertSame(['subject', 'resource'], \array_keys($builders));
        self::assertSame([], $posts->calls);
    }

    /**
     * The subject's namespace depends on the request alone when its type has no
     * attribute provider, or one marked `ScopeInvariant`, and not when its
     * provider is unmarked.
     *
     * @return void
     */
    public function testTheSubjectIsScopeInvariantWhenItsProviderIsMarkedOrAbsent(): void
    {
        $subject = new Subject(new \stdClass);

        self::assertTrue((new AttributeNamespaces)->isSubjectScopeInvariant($subject));
        self::assertTrue((new AttributeNamespaces(new AttributeProviders(new Container)))->isSubjectScopeInvariant($subject));
        $marked   = new AttributeProviders(new Container, [], [\stdClass::class => InvariantSubjectAttributes::class]);
        $unmarked = new AttributeProviders(new Container, [], [\stdClass::class => RecordingSubjectAttributes::class]);

        self::assertTrue((new AttributeNamespaces($marked))->isSubjectScopeInvariant($subject));
        self::assertFalse((new AttributeNamespaces($unmarked))->isSubjectScopeInvariant($subject));
    }

    /**
     * In a bulk check, the resource's namespace is built from the batch's bulk
     * read.
     *
     * @return void
     */
    public function testABulkChecksResourceIsBuiltFromItsBatch(): void
    {
        $container = new Container;
        $provider  = new FixedBulkAttributes;
        $record    = ResourceReference::record('post', '1');

        $container->instance(FixedBulkAttributes::class, $provider);

        $namespaces = new AttributeNamespaces(new AttributeProviders($container, ['post' => FixedBulkAttributes::class]));

        $batched = $namespaces->builders(null, $record, new ResourceAttributeBatch([$record]))['resource']();

        self::assertSame(['resource' => ['id' => '1', 'type' => 'post', 'status' => 'published']], $batched);
        self::assertSame(['resource' => ['id' => '1', 'type' => 'post', 'status' => 'draft']], $namespaces->builders(null, $record)['resource']());
    }

    /**
     * Build a check context holding only the namespaces of the subject and
     * resource, with no providers.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckContext
     */
    private static function context(?Subject $subject, ?ResourceReference $resource): CheckContext
    {
        return new CheckContext([], (new AttributeNamespaces)->builders($subject, $resource));
    }

    /**
     * Build a plain subject answering `getKey()` and `getMorphClass()` as
     * given.
     *
     * @param  mixed  $key
     * @param  string  $type
     * @return object
     */
    private static function keyed(mixed $key, string $type): object
    {
        return new readonly class ($key, $type) {
            /**
             * Create the subject.
             *
             * @param  mixed  $key
             * @param  string  $type
             */
            public function __construct(

                /** The key the subject answers. */
                private mixed $key,

                /** The morph class the subject answers. */
                private string $type,
            ) {}

            /**
             * Return the subject's key.
             *
             * @return mixed
             */
            public function getKey(): mixed
            {
                return $this->key;
            }

            /**
             * Return the subject's morph class.
             *
             * @return string
             */
            public function getMorphClass(): string
            {
                return $this->type;
            }
        };
    }
}
