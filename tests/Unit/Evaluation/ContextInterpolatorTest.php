<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;

/**
 * Unit tests for the context variable interpolator.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(ContextInterpolator::class)]
final class ContextInterpolatorTest extends TestCase
{
    /** @var \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator The interpolator under test. */
    private ContextInterpolator $interpolator;

    /**
     * Set up the test fixtures.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->interpolator = new ContextInterpolator;
    }

    /**
     * Tear down the test fixtures, discarding any container a test installed to
     * capture log output.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance(null);

        parent::tearDown();
    }

    // ------------------------------------------------------------------
    // Context namespaces
    // ------------------------------------------------------------------

    /**
     * `${input.tenant_id}` resolves from the check's `input` namespace.
     *
     * @return void
     */
    public function testContextKeyResolvesFromArray(): void
    {
        $interpolated = $this->interpolator->interpolate(
            'tenant:${input.tenant_id}',
            null,
            null,
            ['input' => ['tenant_id' => 'org-42']],
        );

        self::assertSame('tenant:org-42', $interpolated);
    }

    /**
     * A nested dot path such as `${input.request.ip}` is read segment by
     * segment.
     *
     * @return void
     */
    public function testNestedDotNotationContext(): void
    {
        $interpolated = $this->interpolator->interpolate(
            'ip:${input.request.ip}',
            null,
            null,
            ['input' => ['request' => ['ip' => '10.0.0.1']]],
        );

        self::assertSame('ip:10.0.0.1', $interpolated);
    }

    /**
     * A token of any namespace but `principal` and `resource` reads the check's
     * context: `${request.ip}`, `${environment.time}` and an application's own
     * namespace alike.
     *
     * @return void
     */
    public function testEveryOtherNamespaceIsReadFromTheContext(): void
    {
        $context = [
            'request'     => ['ip' => '10.0.0.1'],
            'environment' => ['time' => '2026-01-31T09:30:00Z'],
            'tenant'      => ['plan' => ['tier' => 'pro']],
        ];

        self::assertSame('10.0.0.1', $this->interpolator->interpolate('${request.ip}', null, null, $context));
        self::assertSame('2026-01-31T09:30:00Z', $this->interpolator->interpolate('${environment.time}', null, null, $context));
        self::assertSame('pro', $this->interpolator->interpolate('${tenant.plan.tier}', null, null, $context));
        self::assertSame('10.0.0.1', $this->interpolator->interpolatePattern('${request.ip}', null, null, new CheckContext($context)));
    }

    /**
     * A token is a dot path, never a literal flat key: a top-level key named
     * `request.ip` does not resolve `${request.ip}`, and neither does a caller
     * value under `input`.
     *
     * @return void
     */
    public function testALiteralDottedKeyIsNotAPath(): void
    {
        $context = ['request.ip' => '10.0.0.1', 'input' => ['request' => ['ip' => '10.0.0.2']]];

        self::assertNull($this->interpolator->interpolate('${request.ip}', null, null, $context));
        self::assertSame('10.0.0.2', $this->interpolator->interpolate('${input.request.ip}', null, null, $context));
    }

    /**
     * The removed `${context.…}` namespace no longer reads what the caller
     * passes: it is a namespace the context does not hold, so it is unresolved.
     *
     * @return void
     */
    public function testTheContextNamespaceIsUnresolved(): void
    {
        self::assertNull($this->interpolator->interpolate('${context.tenant_id}', null, null, ['input' => ['tenant_id' => 'org-1'], 'tenant_id' => 'org-1']));
    }

    /**
     * A token builds only the namespace it reads, once for the context it is
     * given, however many tokens read it.
     *
     * @return void
     */
    public function testATokenBuildsOnlyTheNamespaceItReads(): void
    {
        $calls   = ['request' => 0, 'environment' => 0];
        $context = new CheckContext([], [
            'request' => static function () use (&$calls): array {
                $calls['request']++;

                return ['request' => ['ip' => '10.0.0.1', 'method' => 'GET']];
            },
            'environment' => static function () use (&$calls): array {
                $calls['environment']++;

                return ['environment' => ['time' => '2026-01-31T09:30:00Z']];
            },
        ]);

        self::assertSame('10.0.0.1/GET', $this->interpolator->interpolate('${request.ip}/${request.method}', null, null, $context));
        self::assertSame('10.0.0.1', $this->interpolator->interpolatePattern('${request.ip}', null, null, $context));
        self::assertSame(['request' => 1, 'environment' => 0], $calls);
    }

    /**
     * Scalar context values are cast to strings: integers and floats print
     * their value, and booleans print `true` or `false`.
     *
     * @return void
     */
    public function testScalarContextValuesAreCastToStrings(): void
    {
        $context = ['input' => ['count' => 42, 'ratio' => 2.5, 'yes' => true, 'no' => false]];

        self::assertSame('42', $this->interpolator->interpolate('${input.count}', null, null, $context));
        self::assertSame('2.5', $this->interpolator->interpolate('${input.ratio}', null, null, $context));
        self::assertSame('true', $this->interpolator->interpolate('${input.yes}', null, null, $context));
        self::assertSame('[false]', $this->interpolator->interpolate('[${input.no}]', null, null, $context));
    }

    /**
     * A context key that is missing, null or not a scalar is unresolved, so the
     * whole string is null.
     *
     * @return void
     */
    public function testMissingNullAndNonScalarContextValuesAreUnresolved(): void
    {
        $context = ['input' => ['nested' => ['a' => 'b'], 'object' => new \stdClass, 'nothing' => null]];

        self::assertNull($this->interpolator->interpolate('v:${input.absent}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('v:${input.nested}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('v:${input.object}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('v:${input.nothing}', null, null, $context));
    }

    /**
     * A bare `${input}` token or one with an empty key is unresolved, even when
     * the context holds an entry under the empty key.
     *
     * @return void
     */
    public function testContextTokenWithoutKeyIsUnresolved(): void
    {
        $context = ['input' => ['' => 'leak', 'key' => 'value']];

        self::assertNull($this->interpolator->interpolate('${input}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('${input.}', null, null, $context));
    }

    // ------------------------------------------------------------------
    // Resource namespace
    // ------------------------------------------------------------------

    /**
     * `${resource.id}` and `${resource.type}` split the resource string at its
     * first colon.
     *
     * @return void
     */
    public function testResourceIdAndTypeSplitAtFirstColon(): void
    {
        self::assertSame('post:99', $this->interpolator->interpolate('post:${resource.id}', null, 'posts:99', []));
        self::assertSame('type:posts', $this->interpolator->interpolate('type:${resource.type}', null, 'posts:99', []));

        // Only the first colon splits; later colons belong to the id.
        self::assertSame('7:8', $this->interpolator->interpolate('${resource.id}', null, 'posts:7:8', []));
        self::assertSame('posts', $this->interpolator->interpolate('${resource.type}', null, 'posts:7:8', []));
    }

    /**
     * The colon-position arithmetic is exact at the boundaries of the resource
     * string: an empty segment resolves to the empty string.
     *
     * @return void
     */
    public function testResourceColonSplitBoundaryPrecision(): void
    {
        self::assertSame('B', $this->interpolator->interpolate('${resource.id}', null, 'A:B', []));
        self::assertSame('A', $this->interpolator->interpolate('${resource.type}', null, 'A:B', []));

        self::assertSame('trailing', $this->interpolator->interpolate('${resource.id}', null, ':trailing', []));
        self::assertSame('[]', $this->interpolator->interpolate('[${resource.type}]', null, ':trailing', []));

        self::assertSame('[]', $this->interpolator->interpolate('[${resource.id}]', null, 'leading:', []));
        self::assertSame('leading', $this->interpolator->interpolate('${resource.type}', null, 'leading:', []));
    }

    /**
     * A resource without a colon is its own type and has no id, so
     * `${resource.id}` is unresolved.
     *
     * @return void
     */
    public function testResourceWithoutColonHasTypeButNoId(): void
    {
        self::assertSame('global', $this->interpolator->interpolate('${resource.type}', null, 'global', []));
        self::assertNull($this->interpolator->interpolate('${resource.id}', null, 'global', []));
        self::assertNull($this->interpolator->interpolate('${resource.id}-${resource.type}', null, 'global', []));
    }

    /**
     * Resource tokens are unresolved without a resource, without a key and for
     * any key other than `id` and `type`.
     *
     * @return void
     */
    public function testResourceTokensUnresolvedWithoutResourceOrKnownKey(): void
    {
        self::assertNull($this->interpolator->interpolate('res:${resource.id}', null, null, []));
        self::assertNull($this->interpolator->interpolate('res:${resource.type}', null, null, []));
        self::assertNull($this->interpolator->interpolate('${resource}', null, 'posts:42', []));
        self::assertNull($this->interpolator->interpolate('${resource.unknown}', null, 'posts:42', []));
    }

    // ------------------------------------------------------------------
    // Principal namespace: plain objects
    // ------------------------------------------------------------------

    /**
     * A plain object principal exposes its public properties.
     *
     * @return void
     */
    public function testPlainObjectPublicPropertyResolves(): void
    {
        $principal       = new \stdClass;
        $principal->id   = 'abc';
        $principal->name = 'Bob';
        $principal->rank = 3;

        self::assertSame('id:abc', $this->interpolator->interpolate('id:${principal.id}', $principal, null, []));
        self::assertSame('Bob', $this->interpolator->interpolate('${principal.name}', $principal, null, []));
        self::assertSame('3', $this->interpolator->interpolate('${principal.rank}', $principal, null, []));
    }

    /**
     * A plain object principal never exposes a protected property, a missing
     * property or a `getAttribute()` method it happens to declare: only
     * Eloquent models are read through `getAttribute()`.
     *
     * @return void
     */
    public function testPlainObjectNonPublicStateIsUnresolved(): void
    {
        $principal = new class {
            /** @var string A public property the interpolator may read. */
            public string $name = 'Alice';

            /** @var string A protected property the interpolator must not read. */
            protected string $secret = 'leak';

            /**
             * Answer every key, to prove the interpolator never calls it.
             *
             * @param  string  $key
             * @return string
             */
            public function getAttribute(string $key): string
            {
                return "attribute-{$key}";
            }
        };

        self::assertSame('Alice', $this->interpolator->interpolate('${principal.name}', $principal, null, []));
        self::assertNull($this->interpolator->interpolate('${principal.secret}', $principal, null, []));
        self::assertNull($this->interpolator->interpolate('${principal.id}', $principal, null, []));
    }

    /**
     * A non-scalar or null public property is unresolved.
     *
     * @return void
     */
    public function testNonScalarPropertyIsUnresolved(): void
    {
        $principal          = new \stdClass;
        $principal->items   = ['a', 'b'];
        $principal->owner   = new \stdClass;
        $principal->nothing = null;

        self::assertNull($this->interpolator->interpolate('${principal.items}', $principal, null, []));
        self::assertNull($this->interpolator->interpolate('${principal.owner}', $principal, null, []));
        self::assertNull($this->interpolator->interpolate('${principal.nothing}', $principal, null, []));
    }

    /**
     * `${principal.type}` returns the morph class when the principal offers
     * one, ahead of any property of the same name.
     *
     * @return void
     */
    public function testPrincipalTypeReturnsMorphClass(): void
    {
        $principal = new class {
            /** @var string A property that must not shadow the morph class. */
            public string $type = 'wrong-path';

            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'user';
            }
        };

        self::assertSame('type:user', $this->interpolator->interpolate('type:${principal.type}', $principal, null, []));
    }

    /**
     * `${principal.type}` falls back to the class name, ahead of any property
     * of the same name, when there is no morph class.
     *
     * @return void
     */
    public function testPrincipalTypeFallsBackToClassName(): void
    {
        $principal       = new \stdClass;
        $principal->type = 'wrong-path';

        self::assertSame(\stdClass::class, $this->interpolator->interpolate('${principal.type}', $principal, null, []));
    }

    /**
     * Principal tokens are unresolved without a principal and without a key.
     *
     * @return void
     */
    public function testPrincipalTokensUnresolvedWithoutPrincipalOrKey(): void
    {
        $principal     = new \stdClass;
        $principal->id = 'abc';

        self::assertNull($this->interpolator->interpolate('user:${principal.id}', null, null, []));
        self::assertNull($this->interpolator->interpolate('user:${principal.type}', null, null, []));
        self::assertNull($this->interpolator->interpolate('${principal}', $principal, null, []));
        self::assertNull($this->interpolator->interpolate('${principal.}', $principal, null, []));
    }

    // ------------------------------------------------------------------
    // Principal namespace: Eloquent models
    // ------------------------------------------------------------------

    /**
     * `${principal.id}` is the model's key and other keys read its attributes.
     *
     * @return void
     */
    public function testModelPrincipalResolvesKeyAndAttributes(): void
    {
        $principal = new class extends Model {};
        $principal->setRawAttributes(['id' => 42, 'name' => 'Alice', 'active' => true]);

        self::assertSame('user:42', $this->interpolator->interpolate('user:${principal.id}', $principal, null, []));
        self::assertSame('Alice', $this->interpolator->interpolate('${principal.name}', $principal, null, []));
        self::assertSame('true', $this->interpolator->interpolate('${principal.active}', $principal, null, []));
        self::assertNull($this->interpolator->interpolate('${principal.missing}', $principal, null, []));
    }

    /**
     * `${principal.id}` resolves through `getKey()`, so a model with a custom
     * primary key resolves its real key rather than an `id` column.
     *
     * @return void
     */
    public function testModelWithCustomPrimaryKeyResolvesPrincipalId(): void
    {
        $principal = new class extends Model {
            /** @var string The primary key column. */
            protected $primaryKey = 'uuid';

            /** @var string The primary key type. */
            protected $keyType = 'string';
        };
        $principal->setRawAttributes(['uuid' => 'u-1', 'id' => 99]);

        self::assertSame('u-1', $this->interpolator->interpolate('${principal.id}', $principal, null, []));
        self::assertSame('u-1', $this->interpolator->interpolate('${principal.uuid}', $principal, null, []));
    }

    /**
     * A model without a key leaves `${principal.id}` unresolved.
     *
     * @return void
     */
    public function testModelWithoutKeyLeavesPrincipalIdUnresolved(): void
    {
        $principal = new class extends Model {};

        self::assertNull($this->interpolator->interpolate('${principal.id}', $principal, null, []));
    }

    /**
     * A hidden attribute is never resolved, even though the model holds it.
     *
     * @return void
     */
    public function testModelHiddenAttributeIsUnresolved(): void
    {
        $principal = new class extends Model {
            /** @var list<string> The attributes hidden from serialisation. */
            protected $hidden = ['secret'];
        };
        $principal->setRawAttributes(['secret' => 'leak', 'name' => 'Alice']);

        self::assertNull($this->interpolator->interpolate('${principal.secret}', $principal, null, []));
        self::assertSame('Alice', $this->interpolator->interpolate('${principal.name}', $principal, null, []));
    }

    /**
     * A model with a non-empty `$visible` resolves only the attributes it
     * lists, while `${principal.id}` still resolves through the key.
     *
     * @return void
     */
    public function testModelVisibleListRestrictsAttributes(): void
    {
        $principal = new class extends Model {
            /** @var list<string> The attributes visible in serialisation. */
            protected $visible = ['name'];
        };
        $principal->setRawAttributes(['id' => 5, 'name' => 'Alice', 'email' => 'alice@example.com']);

        self::assertSame('Alice', $this->interpolator->interpolate('${principal.name}', $principal, null, []));
        self::assertNull($this->interpolator->interpolate('${principal.email}', $principal, null, []));
        self::assertSame('5', $this->interpolator->interpolate('${principal.id}', $principal, null, []));
    }

    /**
     * An empty `$visible` allows every attribute that is not hidden, and an
     * attribute both visible and hidden stays unresolved.
     *
     * @return void
     */
    public function testModelEmptyVisibleListAllowsEverythingNotHidden(): void
    {
        $open = new class extends Model {
            /** @var list<string> The attributes visible in serialisation. */
            protected $visible = [];

            /** @var list<string> The attributes hidden from serialisation. */
            protected $hidden = ['secret'];
        };
        $open->setRawAttributes(['name' => 'Alice', 'email' => 'alice@example.com', 'secret' => 'leak']);

        self::assertSame('Alice', $this->interpolator->interpolate('${principal.name}', $open, null, []));
        self::assertSame('alice@example.com', $this->interpolator->interpolate('${principal.email}', $open, null, []));
        self::assertNull($this->interpolator->interpolate('${principal.secret}', $open, null, []));

        $both = new class extends Model {
            /** @var list<string> The attributes visible in serialisation. */
            protected $visible = ['name', 'secret'];

            /** @var list<string> The attributes hidden from serialisation. */
            protected $hidden = ['secret'];
        };
        $both->setRawAttributes(['name' => 'Alice', 'secret' => 'leak']);

        self::assertSame('Alice', $this->interpolator->interpolate('${principal.name}', $both, null, []));
        self::assertNull($this->interpolator->interpolate('${principal.secret}', $both, null, []));
    }

    /**
     * A relation name is never resolved, even when an attribute of the same
     * name is present.
     *
     * @return void
     */
    public function testModelRelationNameIsUnresolved(): void
    {
        $principal = new class extends Model {
            /**
             * A relation the interpolator must not read.
             *
             * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Illuminate\Database\Eloquent\Model, $this>
             */
            public function team(): BelongsTo
            {
                return $this->belongsTo(Model::class);
            }
        };
        $principal->setRawAttributes(['team' => 'leak', 'name' => 'Alice']);

        self::assertNull($this->interpolator->interpolate('${principal.team}', $principal, null, []));
        self::assertSame('Alice', $this->interpolator->interpolate('${principal.name}', $principal, null, []));
    }

    /**
     * A non-scalar model attribute is unresolved.
     *
     * @return void
     */
    public function testModelNonScalarAttributeIsUnresolved(): void
    {
        $principal = new class extends Model {};
        $principal->setRawAttributes(['meta' => ['a' => 'b']]);

        self::assertNull($this->interpolator->interpolate('${principal.meta}', $principal, null, []));
    }

    /**
     * `${principal.type}` on a model is its morph class.
     *
     * @return void
     */
    public function testModelPrincipalTypeIsMorphClass(): void
    {
        $principal = new class extends Model {};
        $principal->setRawAttributes(['type' => 'wrong-path']);

        self::assertSame($principal->getMorphClass(), $this->interpolator->interpolate('${principal.type}', $principal, null, []));
    }

    // ------------------------------------------------------------------ Tokens
    // and escapes
    // ------------------------------------------------------------------

    /**
     * Multiple tokens across every namespace resolve in one string.
     *
     * @return void
     */
    public function testMultipleTokensAllResolve(): void
    {
        $principal     = new \stdClass;
        $principal->id = 7;

        $interpolated = $this->interpolator->interpolate(
            '${principal.id}:${input.env}:${resource.type}:${resource.id}',
            $principal,
            'posts:1',
            ['input' => ['env' => 'prod']],
        );

        self::assertSame('7:prod:posts:1', $interpolated);
    }

    /**
     * One unresolved token among several makes the whole result null rather
     * than leaving a gap in the string.
     *
     * @return void
     */
    public function testOneUnresolvedTokenMakesWholeResultNull(): void
    {
        $context = ['input' => ['env' => 'prod']];

        self::assertNull($this->interpolator->interpolate('${input.env}:${input.missing}:${resource.type}', null, 'posts:1', $context));
        self::assertNull($this->interpolator->interpolate('${input.missing}:${input.env}', null, null, $context));
        self::assertNull($this->interpolator->interpolatePattern('${input.env}/${input.missing}/*', null, null, $context));
    }

    /**
     * A token in an unknown namespace is unresolved.
     *
     * @return void
     */
    public function testUnknownNamespaceIsUnresolved(): void
    {
        self::assertNull($this->interpolator->interpolate('prefix:${unknown.key}:suffix', null, null, ['input' => ['key' => 'value']]));
        self::assertNull($this->interpolator->interpolate('${_private.key}', null, null, []));
    }

    /**
     * Token names may contain letters, digits, underscores and dots; a `$` that
     * does not open a `${` is literal text.
     *
     * @return void
     */
    public function testTokenGrammar(): void
    {
        $context = ['input' => ['Key_9' => 'ok', 'a' => ['b2' => 'deep']]];

        self::assertSame('ok', $this->interpolator->interpolate('${input.Key_9}', null, null, $context));
        self::assertSame('deep', $this->interpolator->interpolate('${input.a.b2}', null, null, $context));
        self::assertSame('$input.a', $this->interpolator->interpolate('$input.a', null, null, $context));
        self::assertSame('$ {input.a}', $this->interpolator->interpolate('$ {input.a}', null, null, $context));
    }

    /**
     * A `${` that does not open a well-formed token is a malformed reference,
     * which makes the whole string unresolved wherever it appears: at the
     * start, after literal text and straight after a real token alike.
     *
     * @return void
     */
    public function testMalformedReferenceMakesWholeResultNull(): void
    {
        $context = ['input' => ['Key_9' => 'ok', 'a' => 'value']];

        self::assertNull($this->interpolator->interpolate('x:${1input.a}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('x:${input-a}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('x:${}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('${input.tenant-id}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('${input-a}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('${}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('${1x}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('${foo', null, null, $context));
        self::assertNull($this->interpolator->interpolate('${input.Key_9}${-}', null, null, $context));
        self::assertNull($this->interpolator->interpolate('${-}${input.Key_9}', null, null, $context));
    }

    /**
     * `containsReference()` is true only when a well-formed, unescaped token is
     * present, whether or not it can be resolved.
     *
     * @return void
     */
    public function testContainsReference(): void
    {
        self::assertTrue(ContextInterpolator::containsReference('${input.a}'));
        self::assertTrue(ContextInterpolator::containsReference('tenant:${unknown.key}:x'));
        self::assertTrue(ContextInterpolator::containsReference('\${literal}:${input.a}'));
        self::assertTrue(ContextInterpolator::containsReference('${input-a}:${input.a}'));

        self::assertFalse(ContextInterpolator::containsReference('\${input.a}'));
        self::assertFalse(ContextInterpolator::containsReference('${input-a}'));
        self::assertFalse(ContextInterpolator::containsReference('${}'));
        self::assertFalse(ContextInterpolator::containsReference('$input.a'));
        self::assertFalse(ContextInterpolator::containsReference('static:pattern'));
        self::assertFalse(ContextInterpolator::containsReference(''));
    }

    /**
     * `references()` lists the path of every well-formed reference, in order,
     * leaving out escaped and malformed ones.
     *
     * @return void
     */
    public function testReferences(): void
    {
        self::assertSame(['request.ip', 'principal.id', 'request.ip'], ContextInterpolator::references('${request.ip}:${principal.id}/${request.ip}'));
        self::assertSame(['input.a'], ContextInterpolator::references('\${literal}:${input-a}:${input.a}'));
        self::assertSame(['environment'], ContextInterpolator::references('${environment}'));
        self::assertSame([], ContextInterpolator::references('\${input.a}:${}:static'));
        self::assertSame([], ContextInterpolator::references(''));
    }

    /**
     * `hasMalformedReference()` is true only when a `${` is neither the `\${`
     * escape nor the start of a well-formed token.
     *
     * @return void
     */
    public function testHasMalformedReference(): void
    {
        self::assertTrue(ContextInterpolator::hasMalformedReference('${input.tenant-id}'));
        self::assertTrue(ContextInterpolator::hasMalformedReference('${}'));
        self::assertTrue(ContextInterpolator::hasMalformedReference('${1x}'));
        self::assertTrue(ContextInterpolator::hasMalformedReference('${foo'));
        self::assertTrue(ContextInterpolator::hasMalformedReference('${input.a}${-}'));
        self::assertTrue(ContextInterpolator::hasMalformedReference('\${x}:${-}'));

        self::assertFalse(ContextInterpolator::hasMalformedReference('${input.a}'));
        self::assertFalse(ContextInterpolator::hasMalformedReference('\${input.a}'));
        self::assertFalse(ContextInterpolator::hasMalformedReference('\${input-a}'));
        self::assertFalse(ContextInterpolator::hasMalformedReference('\${x}:${input.a}'));
        self::assertFalse(ContextInterpolator::hasMalformedReference('$input.a'));
        self::assertFalse(ContextInterpolator::hasMalformedReference('static:pattern'));
        self::assertFalse(ContextInterpolator::hasMalformedReference(''));
    }

    /**
     * A string without tokens passes through unchanged.
     *
     * @return void
     */
    public function testStringWithNoTokensPassesThrough(): void
    {
        self::assertSame('static:pattern', $this->interpolator->interpolate('static:pattern', null, null, []));
        self::assertSame('', $this->interpolator->interpolate('', null, null, []));
    }

    /**
     * `\${…}` passes through as a literal `${…}` and is not interpolated.
     *
     * @return void
     */
    public function testEscapedTokenPassesThroughAsLiteral(): void
    {
        $interpolated = $this->interpolator->interpolate(
            'literal:\${input.a}',
            null,
            null,
            ['input' => ['a' => 'resolved']],
        );

        self::assertSame('literal:${input.a}', $interpolated);
    }

    /**
     * Escaped and unescaped tokens in the same string are each handled on their
     * own.
     *
     * @return void
     */
    public function testEscapedAndUnescapedTokensInSameString(): void
    {
        $interpolated = $this->interpolator->interpolate(
            '${input.a}:\${literal}:${input.a}',
            null,
            null,
            ['input' => ['a' => 'resolved']],
        );

        self::assertSame('resolved:${literal}:resolved', $interpolated);
    }

    /**
     * A substituted value is inserted verbatim: an escape sequence or a token
     * inside it is neither unescaped nor interpolated.
     *
     * @return void
     */
    public function testSubstitutedValueIsNotRewritten(): void
    {
        $context = ['input' => ['escaped' => 'a\${b}', 'token' => '${input.other}', 'other' => 'leak']];

        self::assertSame('a\${b}', $this->interpolator->interpolate('${input.escaped}', null, null, $context));
        self::assertSame('x:${input.other}', $this->interpolator->interpolate('x:${input.token}', null, null, $context));
    }

    /**
     * `interpolate()` leaves backslashes in the literal text untouched.
     *
     * @return void
     */
    public function testInterpolateKeepsLiteralBackslashes(): void
    {
        $interpolated = $this->interpolator->interpolate(
            'App\Models\Post:${input.id}',
            null,
            null,
            ['input' => ['id' => '1']],
        );

        self::assertSame('App\Models\Post:1', $interpolated);
    }

    // ------------------------------------------------------------------
    // Patterns
    // ------------------------------------------------------------------

    /**
     * `interpolatePattern()` escapes every glob special character and the
     * backslash in a substituted value, so it only ever matches itself.
     *
     * @return void
     */
    public function testInterpolatePatternEscapesSubstitutedValues(): void
    {
        $context = ['input' => ['name' => 'a*b?c[d]e\f']];

        $pattern = $this->interpolator->interpolatePattern('files/${input.name}', null, null, $context);

        self::assertSame('files/a\*b\?c\[d\]e\\\f', $pattern);
        self::assertTrue(\fnmatch($pattern, 'files/a*b?c[d]e\f'));
        self::assertFalse(\fnmatch($pattern, 'files/aXbYcde\f'));
    }

    /**
     * A substituted wildcard never widens the pattern: a value of `*` only
     * matches a literal `*`.
     *
     * @return void
     */
    public function testInterpolatePatternWildcardValueMatchesOnlyItself(): void
    {
        $pattern = $this->interpolator->interpolatePattern('docs:${input.id}', null, null, ['input' => ['id' => '*']]);

        self::assertSame('docs:\*', $pattern);
        self::assertTrue(\fnmatch($pattern, 'docs:*'));
        self::assertFalse(\fnmatch($pattern, 'docs:42'));
    }

    /**
     * The pattern's own text keeps its glob meaning, with its backslashes
     * doubled so they stay literal.
     *
     * @return void
     */
    public function testInterpolatePatternDoublesLiteralBackslashes(): void
    {
        $pattern = $this->interpolator->interpolatePattern('App\Models\*:${input.id}', null, null, ['input' => ['id' => '1']]);

        self::assertSame('App\\\Models\\\*:1', $pattern);
        self::assertTrue(\fnmatch($pattern, 'App\Models\Post:1'));
        self::assertFalse(\fnmatch($pattern, 'App\Models\Post:2'));
    }

    /**
     * `\${` in a pattern produces a literal `${`, and a substituted value
     * containing `\${` keeps its backslash escaped rather than being unescaped.
     *
     * @return void
     */
    public function testInterpolatePatternHandlesEscapeSequence(): void
    {
        $context = ['input' => ['escaped' => 'a\${b}']];

        self::assertSame('${input.x}*', $this->interpolator->interpolatePattern('\${input.x}*', null, null, $context));

        $pattern = $this->interpolator->interpolatePattern('${input.escaped}', null, null, $context);

        self::assertSame('a\\\${b}', $pattern);
        self::assertTrue(\fnmatch($pattern, 'a\${b}'));
    }

    /**
     * `interpolatePattern()` returns null for an unresolved token and the
     * pattern unchanged apart from backslashes when there are none.
     *
     * @return void
     */
    public function testInterpolatePatternUnresolvedAndTokenless(): void
    {
        self::assertNull($this->interpolator->interpolatePattern('docs:${resource.id}', null, 'global', []));
        self::assertSame('docs:*', $this->interpolator->interpolatePattern('docs:*', null, null, []));
    }

    /**
     * `interpolatePattern()` returns null for a pattern holding a malformed
     * reference, even beside a token that resolves.
     *
     * @return void
     */
    public function testInterpolatePatternMalformedReferenceIsNull(): void
    {
        $context = ['input' => ['a' => 'value']];

        self::assertNull($this->interpolator->interpolatePattern('${input-a}', null, null, $context));
        self::assertNull($this->interpolator->interpolatePattern('docs:${input.tenant-id}*', null, null, $context));
        self::assertNull($this->interpolator->interpolatePattern('${input.a}/${}', null, null, $context));
    }

    /**
     * `literalPattern()` doubles backslashes and leaves every other character,
     * including glob wildcards and token syntax, as it is.
     *
     * @return void
     */
    public function testLiteralPatternDoublesBackslashes(): void
    {
        self::assertSame('App\\\Models\\\*', ContextInterpolator::literalPattern('App\Models\*'));
        self::assertSame('docs:${input.id}?[a]', ContextInterpolator::literalPattern('docs:${input.id}?[a]'));
        self::assertTrue(\fnmatch(ContextInterpolator::literalPattern('App\Models\*'), 'App\Models\Post'));
    }

    // ------------------------------------------------------------------
    // Logging
    // ------------------------------------------------------------------

    /**
     * An unresolved token is logged at debug level once, naming the token, and
     * resolution stops at the first unresolved token.
     *
     * @return void
     */
    public function testUnresolvedTokenIsLogged(): void
    {
        $logger = new class extends AbstractLogger {
            /** @var list<string> The messages received, prefixed with their level. */
            public array $messages = [];

            /**
             * Record a message with its level.
             *
             * @param  mixed  $level
             * @param  string|\Stringable  $message
             * @param  array<array-key, mixed>  $context
             * @return void
             */
            #[\Override]
            public function log(mixed $level, string|\Stringable $message, array $context = []): void
            {
                $this->messages[] = (\is_string($level) ? $level : 'unknown') . ': ' . $message;
            }
        };

        $container = new Container;
        $container->instance('log', $logger);
        Container::setInstance($container);

        self::assertNull($this->interpolator->interpolate('${input.a}:${input.first}:${input.second}', null, null, ['input' => ['a' => 'x']]));
        self::assertSame(['debug: Unresolved interpolation token \'${input.first}\': the test is undecidable.'], $logger->messages);

        self::assertSame('x', $this->interpolator->interpolate('${input.a}', null, null, ['input' => ['a' => 'x']]));
        self::assertCount(1, $logger->messages);
    }

    /**
     * A logger that throws never aborts interpolation: the token is still
     * unresolved.
     *
     * @return void
     */
    public function testThrowingLoggerDoesNotAbortInterpolation(): void
    {
        $logger = new class extends AbstractLogger {
            /**
             * Fail on every message.
             *
             * @param  mixed  $level
             * @param  string|\Stringable  $message
             * @param  array<array-key, mixed>  $context
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function log(mixed $level, string|\Stringable $message, array $context = []): void
            {
                throw new \RuntimeException("logger unavailable: {$message}");
            }
        };

        $container = new Container;
        $container->instance('log', $logger);
        Container::setInstance($container);

        self::assertNull($this->interpolator->interpolate('${input.missing}', null, null, []));
        self::assertNull($this->interpolator->interpolatePattern('${input.missing}', null, null, []));
    }

    /**
     * Without a logger bound in the container the unresolved token is still
     * reported as null, without raising.
     *
     * @return void
     */
    public function testUnboundLoggerDoesNotAbortInterpolation(): void
    {
        Container::setInstance(new Container);

        self::assertNull($this->interpolator->interpolate('${input.missing}', null, null, []));
    }
}
