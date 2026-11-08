<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use Illuminate\Container\Container;
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
            ['input' => ['request' => ['ip' => '10.0.0.1']]],
        );

        self::assertSame('ip:10.0.0.1', $interpolated);
    }

    /**
     * A token reads the check's context: `${request.ip}`, `${environment.time}`
     * and an application's own namespace alike.
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

        self::assertSame('10.0.0.1', $this->interpolator->interpolate('${request.ip}', $context));
        self::assertSame('2026-01-31T09:30:00Z', $this->interpolator->interpolate('${environment.time}', $context));
        self::assertSame('pro', $this->interpolator->interpolate('${tenant.plan.tier}', $context));
        self::assertSame('10.0.0.1', $this->interpolator->interpolatePattern('${request.ip}', new CheckContext($context)));
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

        self::assertNull($this->interpolator->interpolate('${request.ip}', $context));
        self::assertSame('10.0.0.2', $this->interpolator->interpolate('${input.request.ip}', $context));
    }

    /**
     * The removed `${context.…}` namespace no longer reads what the caller
     * passes: it is a namespace the context does not hold, so it is unresolved.
     *
     * @return void
     */
    public function testTheContextNamespaceIsUnresolved(): void
    {
        self::assertNull($this->interpolator->interpolate('${context.tenant_id}', ['input' => ['tenant_id' => 'org-1'], 'tenant_id' => 'org-1']));
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

        self::assertSame('10.0.0.1/GET', $this->interpolator->interpolate('${request.ip}/${request.method}', $context));
        self::assertSame('10.0.0.1', $this->interpolator->interpolatePattern('${request.ip}', $context));
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

        self::assertSame('42', $this->interpolator->interpolate('${input.count}', $context));
        self::assertSame('2.5', $this->interpolator->interpolate('${input.ratio}', $context));
        self::assertSame('true', $this->interpolator->interpolate('${input.yes}', $context));
        self::assertSame('[false]', $this->interpolator->interpolate('[${input.no}]', $context));
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

        self::assertNull($this->interpolator->interpolate('v:${input.absent}', $context));
        self::assertNull($this->interpolator->interpolate('v:${input.nested}', $context));
        self::assertNull($this->interpolator->interpolate('v:${input.object}', $context));
        self::assertNull($this->interpolator->interpolate('v:${input.nothing}', $context));
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

        self::assertNull($this->interpolator->interpolate('${input}', $context));
        self::assertNull($this->interpolator->interpolate('${input.}', $context));
    }

    // ------------------------------------------------------------------
    // Subject and resource namespaces
    // ------------------------------------------------------------------

    /**
     * `${subject.…}` and `${resource.…}` read the check's `subject` and
     * `resource` namespaces through the same resolver as any other.
     *
     * @return void
     */
    public function testSubjectAndResourceReadTheirNamespaces(): void
    {
        $context = [
            'subject'  => ['id' => '7', 'type' => 'user', 'department' => 'sales'],
            'resource' => ['id' => '42', 'type' => 'post', 'owner' => ['id' => '7']],
        ];

        self::assertSame('user:7', $this->interpolator->interpolate('${subject.type}:${subject.id}', $context));
        self::assertSame('post:42', $this->interpolator->interpolate('${resource.type}:${resource.id}', $context));
        self::assertSame('7/sales', $this->interpolator->interpolate('${resource.owner.id}/${subject.department}', $context));
        self::assertSame('post:42', $this->interpolator->interpolatePattern('${resource.type}:${resource.id}', new CheckContext($context)));
    }

    /**
     * A resource with no id leaves `${resource.id}` unresolved: it is never
     * read by splitting the identifier, and a check with no resource or subject
     * leaves every token of the namespace unresolved.
     *
     * @return void
     */
    public function testAMissingIdIsNeverInferred(): void
    {
        self::assertNull($this->interpolator->interpolate('${resource.id}', ['resource' => ['type' => 'post']]));
        self::assertNull($this->interpolator->interpolate('${resource.id}', ['input' => ['resource' => 'post:42']]));
        self::assertNull($this->interpolator->interpolate('${resource.type}', []));
        self::assertNull($this->interpolator->interpolate('${subject.id}', []));
        self::assertNull($this->interpolator->interpolate('${resource}', ['resource' => ['id' => '42']]));
    }

    /**
     * `${principal.…}` is no namespace of the check's context, so it is
     * unresolved whatever the check is about.
     *
     * @return void
     */
    public function testPrincipalIsUnresolved(): void
    {
        $context = ['subject' => ['id' => '7', 'type' => 'user']];

        self::assertNull($this->interpolator->interpolate('${principal.id}', $context));
        self::assertNull($this->interpolator->interpolate('${principal.type}', $context));
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
        $interpolated = $this->interpolator->interpolate(
            '${subject.id}:${input.env}:${resource.type}:${resource.id}',
            ['subject' => ['id' => '7'], 'resource' => ['type' => 'posts', 'id' => '1'], 'input' => ['env' => 'prod']],
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

        self::assertNull($this->interpolator->interpolate('${input.env}:${input.missing}:${resource.type}', $context));
        self::assertNull($this->interpolator->interpolate('${input.missing}:${input.env}', $context));
        self::assertNull($this->interpolator->interpolatePattern('${input.env}/${input.missing}/*', $context));
    }

    /**
     * A token in an unknown namespace is unresolved.
     *
     * @return void
     */
    public function testUnknownNamespaceIsUnresolved(): void
    {
        self::assertNull($this->interpolator->interpolate('prefix:${unknown.key}:suffix', ['input' => ['key' => 'value']]));
        self::assertNull($this->interpolator->interpolate('${_private.key}', []));
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

        self::assertSame('ok', $this->interpolator->interpolate('${input.Key_9}', $context));
        self::assertSame('deep', $this->interpolator->interpolate('${input.a.b2}', $context));
        self::assertSame('$input.a', $this->interpolator->interpolate('$input.a', $context));
        self::assertSame('$ {input.a}', $this->interpolator->interpolate('$ {input.a}', $context));
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

        self::assertNull($this->interpolator->interpolate('x:${1input.a}', $context));
        self::assertNull($this->interpolator->interpolate('x:${input-a}', $context));
        self::assertNull($this->interpolator->interpolate('x:${}', $context));
        self::assertNull($this->interpolator->interpolate('${input.tenant-id}', $context));
        self::assertNull($this->interpolator->interpolate('${input-a}', $context));
        self::assertNull($this->interpolator->interpolate('${}', $context));
        self::assertNull($this->interpolator->interpolate('${1x}', $context));
        self::assertNull($this->interpolator->interpolate('${foo', $context));
        self::assertNull($this->interpolator->interpolate('${input.Key_9}${-}', $context));
        self::assertNull($this->interpolator->interpolate('${-}${input.Key_9}', $context));
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
        self::assertSame('static:pattern', $this->interpolator->interpolate('static:pattern', []));
        self::assertSame('', $this->interpolator->interpolate('', []));
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

        self::assertSame('a\${b}', $this->interpolator->interpolate('${input.escaped}', $context));
        self::assertSame('x:${input.other}', $this->interpolator->interpolate('x:${input.token}', $context));
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

        $pattern = $this->interpolator->interpolatePattern('files/${input.name}', $context);

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
        $pattern = $this->interpolator->interpolatePattern('docs:${input.id}', ['input' => ['id' => '*']]);

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
        $pattern = $this->interpolator->interpolatePattern('App\Models\*:${input.id}', ['input' => ['id' => '1']]);

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

        self::assertSame('${input.x}*', $this->interpolator->interpolatePattern('\${input.x}*', $context));

        $pattern = $this->interpolator->interpolatePattern('${input.escaped}', $context);

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
        self::assertNull($this->interpolator->interpolatePattern('docs:${resource.id}', []));
        self::assertSame('docs:*', $this->interpolator->interpolatePattern('docs:*', []));
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

        self::assertNull($this->interpolator->interpolatePattern('${input-a}', $context));
        self::assertNull($this->interpolator->interpolatePattern('docs:${input.tenant-id}*', $context));
        self::assertNull($this->interpolator->interpolatePattern('${input.a}/${}', $context));
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

        self::assertNull($this->interpolator->interpolate('${input.a}:${input.first}:${input.second}', ['input' => ['a' => 'x']]));
        self::assertSame(['debug: Unresolved interpolation token \'${input.first}\': the test is undecidable.'], $logger->messages);

        self::assertSame('x', $this->interpolator->interpolate('${input.a}', ['input' => ['a' => 'x']]));
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

        self::assertNull($this->interpolator->interpolate('${input.missing}', []));
        self::assertNull($this->interpolator->interpolatePattern('${input.missing}', []));
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

        self::assertNull($this->interpolator->interpolate('${input.missing}', []));
    }

    /**
     * A reference that cannot be resolved is noted with an explained context,
     * by its key, and one that resolves is not.
     *
     * @return void
     */
    public function testAnUnresolvedReferenceIsNotedWithTheContext(): void
    {
        $context = new CheckContext(['input' => ['a' => 'x', 'list' => ['y']]]);

        $context->explain();

        self::assertNull((new ContextInterpolator)->interpolate('${input.a}/${input.list}', $context));
        self::assertNull((new ContextInterpolator)->interpolatePattern('${input.missing}', $context));
        self::assertSame('x', (new ContextInterpolator)->interpolate('${input.a}', $context));
        self::assertSame(['input.list', 'input.missing'], $context->takeUnresolved());
    }
}
