<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Diagnostics\BootCheck;
use SineMacula\Laravel\Authorization\Diagnostics\BootChecks;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\BootCheckOutcome;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Tests\Feature\Stubs\PlanContextSource;
use Tests\Feature\Stubs\ReservedContextSource;
use Tests\Fixtures\Diagnostics\ThrowingContextSource;
use Tests\TestCase;

/**
 * Feature tests for the checks the boot runs by building what the configuration
 * names, each run on its own and its outcome recorded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BootChecks::class)]
final class BootChecksTest extends TestCase
{
    /**
     * As none ran, each check's outcome is `not_run`, in the order they run.
     *
     * @return void
     */
    public function testNoneRun(): void
    {
        $expected = [
            'authorization.context.sources',
            'authorization.attributes.resources',
            'authorization.attributes.subjects',
            'authorization.session.scopes',
            'authorization.cache.store',
        ];

        self::assertSame($expected, BootChecks::paths());
        self::assertSame($expected, \array_map(static fn (BootCheck $check): string => $check->path, BootChecks::notRun()));
        self::assertSame(\array_fill(0, 5, BootCheckOutcome::NOT_RUN), self::outcomes(BootChecks::notRun()));
    }

    /**
     * On the shipped configuration, the authentication context is built and
     * passes, and the checks with nothing to build do not run.
     *
     * @return void
     */
    public function testWithNothingNamedOnlyTheContextIsBuilt(): void
    {
        [$checks, $issues] = (new BootChecks($this->container()))->run($this->authorizationConfig());

        self::assertSame([], $issues);
        self::assertSame([BootCheckOutcome::PASSED, ...\array_fill(0, 4, BootCheckOutcome::NOT_RUN)], self::outcomes($checks));
    }

    /**
     * Each check naming something to build runs and passes when it builds.
     *
     * @return void
     */
    public function testEachCheckRunsWhenItHasSomethingToBuild(): void
    {
        $config = $this->authorizationConfig();

        $config['context']['sources'] = [PlanContextSource::class];
        $config['session']['scopes']  = ['posts.read'];
        $config['cache']['store']     = 'array';

        [$checks, $issues] = (new BootChecks($this->container()))->run($config);

        self::assertSame([], $issues);
        $ran     = BootCheckOutcome::PASSED;
        $skipped = BootCheckOutcome::NOT_RUN;

        self::assertSame([$ran, $skipped, $skipped, $ran, $ran], self::outcomes($checks));
    }

    /**
     * A check refusing what it built records the refusal and fails with the
     * refusal's class; one failing in a way the package did not foresee is
     * recorded as `internal`, with the exception's class alone; the other
     * checks still run.
     *
     * @return void
     */
    public function testEachFailureIsRecordedOnItsOwn(): void
    {
        $config = $this->authorizationConfig();

        $config['cache']['store'] = 'missing';

        [$checks, $issues] = (new BootChecks($this->container()))->run($config);

        self::assertSame(BootCheckOutcome::PASSED, $checks[0]->outcome);
        self::assertSame([BootCheckOutcome::FAILED, InvalidAuthorizationConfigException::class], [$checks[4]->outcome, $checks[4]->exception]);
        self::assertSame([['authorization.cache.store', IssueCode::UNKNOWN_NAME]], self::pathsAndCodes($issues));

        $config['context']['sources'] = [ThrowingContextSource::class];

        [$checks, $issues] = (new BootChecks($this->container()))->run($config);

        self::assertSame([BootCheckOutcome::FAILED, \RuntimeException::class], [$checks[0]->outcome, $checks[0]->exception]);
        self::assertSame([['authorization.context.sources', IssueCode::INTERNAL], ['authorization.cache.store', IssueCode::UNKNOWN_NAME]], self::pathsAndCodes($issues));
        self::assertSame(\RuntimeException::class, $issues[0]->exception);

        $config['context']['sources'] = [ReservedContextSource::class];

        [, $issues] = (new BootChecks($this->container()))->run($config);

        self::assertSame(['authorization.context.sources.0', IssueCode::INVALID_VALUE], self::pathsAndCodes($issues)[0]);
    }

    /**
     * The attribute providers are built when either list names one, the
     * subjects' alone included, and both settings share the outcome, each under
     * its own path, the refusal recorded at the setting it names.
     *
     * @return void
     */
    public function testTheAttributeProvidersAreBuiltForEitherList(): void
    {
        $config = $this->authorizationConfig();

        $config['attributes'] = ['resources' => [], 'subjects' => ['user' => \stdClass::class]];

        [$checks, $issues] = (new BootChecks($this->container()))->run($config);

        self::assertSame(BootChecks::ATTRIBUTES, [$checks[1]->path, $checks[2]->path]);
        self::assertSame([BootCheckOutcome::FAILED, BootCheckOutcome::FAILED], [$checks[1]->outcome, $checks[2]->outcome]);
        self::assertSame([InvalidAuthorizationConfigException::class, InvalidAuthorizationConfigException::class], [$checks[1]->exception, $checks[2]->exception]);
        self::assertCount(1, $issues);
        self::assertStringStartsWith(BootChecks::ATTRIBUTES[1], $issues[0]->path);
    }

    /**
     * A block that is not an array is read as none, so its check has nothing to
     * build.
     *
     * @return void
     */
    public function testABlockThatIsNoArrayIsReadAsNone(): void
    {
        $config = $this->authorizationConfig();

        $config['cache'] = 'array';

        [$checks] = (new BootChecks($this->container()))->run($config);

        self::assertSame(BootCheckOutcome::NOT_RUN, $checks[4]->outcome);
    }

    /**
     * Return the outcome of each check.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\BootCheck>  $checks
     * @return list<\SineMacula\Laravel\Authorization\Diagnostics\Enums\BootCheckOutcome>
     */
    private static function outcomes(array $checks): array
    {
        return \array_map(static fn (BootCheck $check): BootCheckOutcome => $check->outcome, $checks);
    }

    /**
     * Return the path and code of each issue.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue>  $issues
     * @return list<array{string, \SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode}>
     */
    private static function pathsAndCodes(array $issues): array
    {
        return \array_map(static fn (ConfigIssue $issue): array => [$issue->path, $issue->code], $issues);
    }
}
