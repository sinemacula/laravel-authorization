<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\ConditionResult;
use SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\PrincipalSelectors;
use SineMacula\Laravel\Authorization\Evaluation\RequirementCheck;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubRequirementChecker;

/**
 * Unit tests for the context of one check: its namespaces, read as dot paths,
 * and built on the first read, once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(CheckContext::class)]
final class CheckContextTest extends TestCase
{
    /** @var array<string, mixed> The namespaces most tests read. */
    private const array NAMESPACES = [
        'request' => ['ip' => '10.0.0.1', 'headers' => ['agent' => 'curl'], 'route' => null],
        'input'   => ['post' => ['status' => 'draft', 'tags' => ['a', 'b']], 'post.status' => 'flat', '' => 'empty'],
        'flag'    => false,
    ];

    /** @var array<string, int> How many times each namespace has been built. */
    private array $builds = [];

    /**
     * Provide paths with whether each is present and its value.
     *
     * @return iterable<string, array{string, bool, mixed}>
     */
    public static function pathProvider(): iterable
    {
        yield 'a key of a namespace' => ['request.ip', true, '10.0.0.1'];
        yield 'a nested key' => ['request.headers.agent', true, 'curl'];
        yield 'a deeply nested key' => ['input.post.status', true, 'draft'];
        yield 'a list' => ['input.post.tags', true, ['a', 'b']];
        yield 'a list element' => ['input.post.tags.1', true, 'b'];
        yield 'a present null' => ['request.route', true, null];
        yield 'a whole namespace' => ['flag', true, false];
        yield 'a missing key' => ['request.method', false, null];
        yield 'a missing namespace' => ['environment.time', false, null];
        yield 'a key under a scalar' => ['request.ip.v4', false, null];
        yield 'a key under a present null' => ['request.route.name', false, null];
        yield 'a key under a false namespace' => ['flag.value', false, null];
        yield 'a literal dotted key' => ['input.post.status.x', false, null];
        yield 'an empty segment' => ['input.', false, null];
        yield 'an empty segment between' => ['input..post', false, null];
        yield 'an empty path' => ['', false, null];
        yield 'a leading dot' => ['.request', false, null];
    }

    /**
     * A path is read segment by segment, and a missing key is kept apart from a
     * key present with a null value.
     *
     * @param  string  $path
     * @param  bool  $isPresent
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('pathProvider')]
    public function testLookupReadsADotPath(string $path, bool $isPresent, mixed $value): void
    {
        $context = new CheckContext(self::NAMESPACES);

        self::assertSame([$isPresent, $value], $context->lookup($path));
        self::assertSame([$isPresent, $value], $context->find(\explode('.', $path)));
    }

    /**
     * A top-level key holding a dot is never a path: `request.ip` reads the
     * `request` namespace, never a key named `request.ip`.
     *
     * @return void
     */
    public function testALiteralDottedTopLevelKeyIsNotAPath(): void
    {
        $context = new CheckContext(['request.ip' => '10.0.0.1', 'input' => ['post.status' => 'flat']]);

        self::assertSame([false, null], $context->lookup('request.ip'));
        self::assertSame([false, null], $context->lookup('input.post.status'));
        self::assertSame([true, 'flat'], $context->find(['input', 'post.status']));
    }

    /**
     * No segments read nothing.
     *
     * @return void
     */
    public function testNoSegmentsAreMissing(): void
    {
        self::assertSame([false, null], (new CheckContext(['' => 'x']))->find([]));
    }

    /**
     * A namespace is built the first time it is read, and only then: a
     * namespace never read is never built, and one read again is not rebuilt.
     *
     * @return void
     */
    public function testANamespaceIsBuiltOnFirstReadAndOnce(): void
    {
        $context = $this->countingContext();

        self::assertSame([], $this->builds);
        self::assertSame([true, '10.0.0.1'], $context->lookup('request.ip'));
        self::assertSame([false, null], $context->lookup('request.method'));
        self::assertSame([true, '10.0.0.1'], $context->find(['request', 'ip']));
        self::assertSame(['request' => 1], $this->builds);

        self::assertSame([true, '2026-01-31T09:30:00Z'], $context->lookup('environment.time'));
        self::assertSame(['request' => 1, 'environment' => 1], $this->builds);
    }

    /**
     * Reading an unknown namespace, a path through a namespace never built, or
     * an empty path builds nothing.
     *
     * @return void
     */
    public function testReadingAnotherNamespaceBuildsNothing(): void
    {
        $context = $this->countingContext();

        self::assertSame([false, null], $context->lookup('tenant.id'));
        self::assertSame([false, null], $context->lookup(''));
        self::assertSame([], $this->builds);
    }

    /**
     * A builder that builds several namespaces runs once for all of them, and a
     * namespace it was to build but left out is absent, without running the
     * builder again.
     *
     * @return void
     */
    public function testABuilderOfSeveralNamespacesRunsOnce(): void
    {
        $calls   = 0;
        $builder = static function () use (&$calls): array {
            $calls++;

            return ['authentication' => ['guard' => 'web'], 'mfa' => ['enrolled' => true], 'stray' => ['x' => 1]];
        };
        $context = new CheckContext([], ['authentication' => $builder, 'sso' => $builder, 'mfa' => $builder]);

        // The namespace the builder leaves out comes before one it builds, so
        // the first read keeps every namespace the builder builds, not only
        // those before the one it leaves out.
        self::assertSame([true, 'web'], $context->lookup('authentication.guard'));
        self::assertSame([true, true], $context->lookup('mfa.enrolled'));
        self::assertSame([false, null], $context->lookup('sso.provider'));
        self::assertSame([false, null], $context->lookup('stray.x'));
        self::assertSame(1, $calls);
    }

    /**
     * A builder runs only for the namespaces it was given for, however alike
     * another builder is: two closures over one method compare equal, yet each
     * builds its own namespace, so each runs once.
     *
     * @return void
     */
    public function testABuilderRunsOnlyForItsOwnNamespaces(): void
    {
        $source = new class {
            /** @var int How many times the namespaces were built. */
            public int $calls = 0;

            /**
             * Build both namespaces.
             *
             * @return array<string, array<string, int>>
             */
            public function build(): array
            {
                $this->calls++;

                return ['a' => ['v' => 1], 'b' => ['v' => 2]];
            }
        };

        $first   = $source->build(...);
        $second  = $source->build(...);
        $context = new CheckContext([], ['a' => $first, 'b' => $second]);

        self::assertEquals($first, $second);
        self::assertSame([true, 1], $context->lookup('a.v'));
        self::assertSame([true, 2], $context->lookup('b.v'));
        self::assertSame(2, $source->calls);
    }

    /**
     * A builder that throws is never run again for the check: the failure
     * reaches the reader, a later read finds every namespace it was to build
     * missing, and the namespaces of other builders are still built.
     *
     * @return void
     */
    public function testABuilderThatThrowsIsNeverRetried(): void
    {
        $calls   = 0;
        $builder = static function () use (&$calls): array {
            $calls++;

            throw new \RuntimeException('provider failed');
        };
        $context = new CheckContext([], [
            'resource' => $builder,
            'subject'  => $builder,
            'request'  => static fn (): array => ['request' => ['ip' => '10.0.0.1']],
        ]);

        try {
            $context->lookup('resource.status');

            self::fail('The builder\'s failure reaches the reader.');
        } catch (\RuntimeException $exception) {
            self::assertSame('provider failed', $exception->getMessage());
        }

        self::assertSame([false, null], $context->lookup('resource.status'));
        self::assertSame([false, null], $context->lookup('subject.id'));
        self::assertSame([true, '10.0.0.1'], $context->lookup('request.ip'));
        self::assertSame(1, $calls);
    }

    /**
     * A namespace a builder leaves out is absent, and its builder is not run
     * again.
     *
     * @return void
     */
    public function testANamespaceLeftOutIsAbsent(): void
    {
        $calls   = 0;
        $context = new CheckContext([], ['request' => static function () use (&$calls): array {
            $calls++;

            return [];
        }]);

        self::assertSame([false, null], $context->lookup('request.ip'));
        self::assertSame([false, null], $context->lookup('request'));
        self::assertSame(1, $calls);
    }

    /**
     * A namespace given already built is never built again, so its builder is
     * ignored, while a namespace given empty is present.
     *
     * @return void
     */
    public function testANamespaceGivenBuiltIsNeverBuilt(): void
    {
        $context = new CheckContext(['input' => []], ['input' => static function (): array {
            self::fail('A namespace given already built is never built.');
        }]);

        self::assertSame([true, []], $context->lookup('input'));
        self::assertSame([false, null], $context->lookup('input.request.ip'));
    }

    /**
     * Each context builds its own namespaces, so a new check builds them again.
     *
     * @return void
     */
    public function testEachContextBuildsItsOwnNamespaces(): void
    {

        $this->countingContext()->lookup('request.ip');
        $this->countingContext()->lookup('request.ip');

        self::assertSame(['request' => 2], $this->builds);
    }

    /**
     * `from()` returns a context as it is, and makes one whose namespaces are
     * an array given.
     *
     * @return void
     */
    public function testFromWrapsAnArrayAndKeepsAContext(): void
    {
        $context = new CheckContext(self::NAMESPACES);

        self::assertSame($context, CheckContext::from($context));
        self::assertEquals($context, CheckContext::from(self::NAMESPACES));
        self::assertSame([true, '10.0.0.1'], CheckContext::from(self::NAMESPACES)->lookup('request.ip'));
        self::assertSame([false, null], CheckContext::from([])->lookup('request.ip'));
    }

    /**
     * A context built without a requirement check meets no requirement, and
     * records that it read one.
     *
     * @return void
     */
    public function testWithoutARequirementCheckNothingIsMet(): void
    {
        $context = new CheckContext(['authentication' => ['multifactor' => true]]);

        self::assertNull($context->requirementFreshness());

        $result = $context->assessRequirement(new AuthenticationRequirement(['multifactor' => null]));

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $result->outcome);
        self::assertSame(['multifactor'], $result->unmetRequirement?->unmet);
        self::assertEquals(new RequirementFreshness(null), $context->requirementFreshness());
    }

    /**
     * A context judges requirements with its requirement check, and reports its
     * freshness, without building any namespace.
     *
     * @return void
     */
    public function testJudgesRequirementsWithItsCheck(): void
    {
        $user    = new \stdClass;
        $builder = function (): array {
            $this->builds['authentication'] = ($this->builds['authentication'] ?? 0) + 1;

            return ['authentication' => ['amr' => ['otp']]];
        };
        $context = new CheckContext([], ['authentication' => $builder], new RequirementCheck(
            new StubRequirementChecker(RequirementResult::met()),
            new Subject($user, $user, session: 'session-1'),
        ));

        self::assertSame(MatchOutcome::MATCHES, $context->assessRequirement(new AuthenticationRequirement(['multifactor' => null]))->outcome);
        self::assertEquals(new RequirementFreshness('session-1'), $context->requirementFreshness());
        self::assertSame([], $this->builds);
    }

    /**
     * A context names every part of every requirement read on it, once each,
     * sorted, met or not, and none before any is read.
     *
     * @return void
     */
    public function testNamesEveryRequirementRead(): void
    {
        $user    = new \stdClass;
        $context = new CheckContext([], [], new RequirementCheck(
            new StubRequirementChecker(RequirementResult::met(), ['phishing_resistant' => RequirementResult::unmet(['phishing_resistant'])]),
            new Subject($user, $user, session: 'session-1'),
        ));

        self::assertSame([], $context->requirementsRead());

        $context->assessRequirement(new AuthenticationRequirement(['phishing_resistant' => null]));
        $context->assessRequirement(new AuthenticationRequirement(['multifactor' => null, 'assurance_level' => null], 'high'));
        $context->assessRequirement(new AuthenticationRequirement(['multifactor' => null]));

        self::assertSame(['assurance_level', 'multifactor', 'phishing_resistant'], $context->requirementsRead());
    }

    /**
     * A context given the subject's selectors asks them whether a resource
     * policy's principals name the subject; one without names nobody.
     *
     * @return void
     */
    public function testIsSubjectNamedByAsksTheSubjectsSelectors(): void
    {
        $user    = new Reference('user', '1');
        $context = new CheckContext([], [], null, new PrincipalSelectors(new Subject($user)));

        self::assertTrue($context->isSubjectNamedBy(['user:2', 'user:1']));
        self::assertFalse($context->isSubjectNamedBy(['user:2']));
        self::assertFalse((new CheckContext)->isSubjectNamedBy(['user:1']));
    }

    /**
     * A context records nothing until it is explained: it then notes each
     * reference it could not resolve, which takeUnresolved() returns once, in
     * order.
     *
     * @return void
     */
    public function testAnExplainedContextNotesUnresolvedReferences(): void
    {
        $context = new CheckContext;

        $context->noteUnresolved('input.a');

        self::assertFalse($context->isExplaining());
        self::assertSame([], $context->takeUnresolved());

        $context->explain();
        $context->noteUnresolved('input.a');
        $context->noteUnresolved('input.b');

        self::assertTrue($context->isExplaining());
        self::assertSame(['input.a', 'input.b'], $context->takeUnresolved());
        self::assertSame([], $context->takeUnresolved());
    }

    /**
     * A reference is noted only when it cannot be resolved, and one into a
     * namespace not yet built is neither looked up nor noted, so the namespace
     * is not built; once it is, its references are noted as any other.
     *
     * @return void
     */
    public function testAReferenceIsNotedOnlyWhenItCannotBeResolved(): void
    {
        $built   = new \ArrayObject;
        $builder = static function () use ($built): array {
            $built->append('resource');

            return ['resource' => ['owner' => 'u']];
        };
        $context = new CheckContext(['input' => ['a' => 'x', 'list' => ['y']]], ['resource' => $builder]);

        foreach (['input.a', 'input.list', 'input.missing', 'resource.owner', 'resource.gone'] as $reference) {
            $context->noteIfUnresolved($reference);
        }

        self::assertSame(['input.list', 'input.missing'], $context->takeUnresolved());
        self::assertCount(0, $built);

        $context->lookup('resource.owner');
        $context->noteIfUnresolved('resource.owner');
        $context->noteIfUnresolved('resource.gone');

        self::assertSame(['resource.gone'], $context->takeUnresolved());
        self::assertCount(1, $built);
    }

    /**
     * A statement whose target did not match notes no tests, only its
     * unresolved references, which are taken as any assessment is.
     *
     * @return void
     */
    public function testAMismatchIsNotedWithoutTests(): void
    {
        $context = new CheckContext;

        $context->noteAssessment(null, ['input.a']);

        self::assertSame([null, ['input.a']], $context->takeAssessment());
        self::assertSame([null, []], $context->takeAssessment());
    }

    /**
     * The tests a statement notes are taken once, with its unresolved
     * references; a context noted with none gives none.
     *
     * @return void
     */
    public function testTheAssessmentNotedIsTakenOnce(): void
    {
        $context = new CheckContext;
        $tests   = [new ConditionResult('input.a', 'eq', ConditionOutcome::HELD)];

        self::assertSame([null, []], $context->takeAssessment());

        $context->noteAssessment($tests, ['input.b']);

        self::assertSame([$tests, ['input.b']], $context->takeAssessment());
        self::assertSame([null, []], $context->takeAssessment());
    }

    /**
     * Build a context whose `request` and `environment` namespaces are built on
     * demand, counting each build.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckContext
     */
    private function countingContext(): CheckContext
    {
        return new CheckContext([], [
            'request' => function (): array {
                $this->builds['request'] = ($this->builds['request'] ?? 0) + 1;

                return ['request' => ['ip' => '10.0.0.1']];
            },
            'environment' => function (): array {
                $this->builds['environment'] = ($this->builds['environment'] ?? 0) + 1;

                return ['environment' => ['time' => '2026-01-31T09:30:00Z']];
            },
        ]);
    }
}
