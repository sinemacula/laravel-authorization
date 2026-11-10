<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\StructuralCheck;
use Tests\Feature\Stubs\PlanContextSource;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\TestCase;

/**
 * Feature tests for checking the configuration as the boot does, collecting
 * every issue instead of throwing the first (N113): several refused settings at
 * once, in a stable order; each unknown key on its own beside a refused
 * sibling; checks skipped for a refused block; an unforeseen failure recorded
 * by its class alone; and the checks that build what the configuration names
 * left to the boot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StructuralCheck::class)]
final class StructuralCheckTest extends TestCase
{
    /** @var string A value that must never appear in what the check reports. */
    private const string SECRET = 'Hunter2Secret';

    /**
     * The configuration the suite boots with passes.
     *
     * @return void
     */
    public function testTheBootedConfigurationPasses(): void
    {
        $findings = $this->check($this->authorizationConfig());

        self::assertSame([], $findings->issues);
        self::assertFalse($findings->isRefused());
        self::assertFalse($findings->isIncomplete());
    }

    /**
     * Several refused settings across the configuration are all listed, each
     * under its own path, in the order the checks run.
     *
     * @return void
     */
    public function testSeveralRefusedSettingsAreAllListedInOrder(): void
    {
        $findings = $this->check([
            ...$this->authorizationConfig(),
            'models'               => ['rol' => 'X', 'role' => 'Missing\Model'],
            'tables'               => ['roles' => 'bad name', 'permissions' => 'ROLES'],
            'permission_providers' => ['Missing\One', 'Missing\Two'],
            'bulk'                 => ['chunk_size' => 0],
            'usage'                => ['enabled' => 'yes'],
            'grant_hooks'          => [ConfigFindings::class],
        ]);

        self::assertSame([
            ['authorization.tables.roles', 'invalid_value'],
            ['authorization.models.rol', 'unknown_key'],
            ['authorization.models.role', 'unknown_class'],
            ['authorization.permission_providers.0', 'unknown_class'],
            ['authorization.permission_providers.1', 'unknown_class'],
            ['authorization.grant_hooks.0', 'not_implemented'],
            ['authorization.bulk.chunk_size', 'out_of_range'],
            ['authorization.usage.enabled', 'invalid_type'],
        ], self::pathsAndCodes($findings));
    }

    /**
     * Each unknown key of a block is refused on its own, and the rest of the
     * block is still checked, a refused sibling among it.
     *
     * @return void
     */
    public function testEachUnknownKeyIsListedBesideARefusedSibling(): void
    {
        $findings = $this->check([...$this->authorizationConfig(), 'cache' => ['stor' => 'array', 'tll' => 5, 'ttl' => 0, 'prefix' => 'p']]);

        self::assertSame([
            ['authorization.cache.stor', 'unknown_key'],
            ['authorization.cache.tll', 'unknown_key'],
            ['authorization.cache.ttl', 'out_of_range'],
        ], self::pathsAndCodes($findings));

        self::assertSame('one of store, ttl, prefix', $findings->issues[0]->expected);
        self::assertSame('int', $findings->issues[2]->gotType);
    }

    /**
     * A block that is not an array is one refusal, and every setting it holds
     * is skipped, naming the block.
     *
     * @return void
     */
    public function testTheSettingsOfARefusedBlockAreSkipped(): void
    {
        $findings = $this->check([...$this->authorizationConfig(), 'cache' => 'redis']);

        self::assertSame([
            ['authorization.cache', 'invalid_type'],
            ['authorization.cache.store', 'skipped'],
            ['authorization.cache.ttl', 'skipped'],
            ['authorization.cache.prefix', 'skipped'],
        ], self::pathsAndCodes($findings));

        self::assertSame('authorization.cache', $findings->issues[1]->dependsOn);
        self::assertSame('skipped', $findings->issues[1]->kind());
        self::assertTrue($findings->isRefused());
    }

    /**
     * A configuration that is not an array is one refusal, and every setting is
     * skipped.
     *
     * @return void
     */
    public function testAConfigurationThatIsNotAnArrayIsOneRefusal(): void
    {
        $findings = $this->check('authorization');
        $refusals = \array_filter($findings->issues, static fn (ConfigIssue $issue): bool => $issue->code->isRefusal());

        self::assertCount(1, $refusals);
        self::assertSame('authorization', $findings->issues[0]->path);
        self::assertCount(\count(ConfigValidator::KEYS) + 1, $findings->issues);
    }

    /**
     * A check that throws what the package did not foresee, a type error among
     * it, is recorded as internal, with the exception's class alone, and the
     * findings are incomplete, not refused.
     *
     * @return void
     */
    public function testAnUnforeseenFailureIsInternal(): void
    {
        foreach ([\RuntimeException::class, \TypeError::class] as $class) {
            $container = new Container;

            $container->instance('config', new class ($class) extends Repository {
                /**
                 * Create a configuration that fails to read.
                 *
                 * @param  class-string<\Throwable>  $failure
                 */
                public function __construct(

                    /** The class of what reading throws. */
                    private readonly string $failure,
                ) {
                    parent::__construct();
                }

                /**
                 * Fail to read the setting.
                 *
                 * @param  mixed  $key
                 * @param  mixed  $default
                 * @return mixed
                 *
                 * @throws \Throwable
                 */
                #[\Override]
                public function get(mixed $key, mixed $default = null): mixed
                {
                    throw new $this->failure('The reader failed with ' . StructuralCheckTest::secret() . '.');
                }
            });

            $findings = (new StructuralCheck($container))->run($this->authorizationConfig());

            self::assertSame(['authorization.connection', 'authorization.defaults.guard'], \array_column(self::pathsAndCodes($findings), 0), $class);
            self::assertSame($class, $findings->issues[0]->exception);
            self::assertSame('internal', $findings->issues[0]->kind());
            self::assertTrue($findings->isIncomplete());
            self::assertFalse($findings->isRefused());
            self::assertStringNotContainsString(self::SECRET, (string) \json_encode(\array_map(static fn (ConfigIssue $issue): array => $issue->toArray(), $findings->issues)));
        }
    }

    /**
     * What each issue says is written by the package and never holds the value
     * the configuration set.
     *
     * @return void
     */
    public function testIssuesNeverHoldTheValuesSet(): void
    {
        $findings = $this->check([
            ...$this->authorizationConfig(),
            'connection'  => self::SECRET,
            'models'      => ['role' => 'Missing\\' . self::SECRET],
            'tables'      => ['roles' => self::SECRET . ' x'],
            'log_channel' => self::SECRET,
            self::SECRET  => self::SECRET,
        ]);

        $issues = (string) \json_encode(\array_map(static fn (ConfigIssue $issue): array => $issue->toArray(), $findings->issues));

        self::assertCount(5, $findings->issues);
        self::assertSame(1, \substr_count($issues, self::SECRET), 'Only the path of the unknown key names it.');
        self::assertStringContainsString('"authorization.' . self::SECRET . '"', $issues);
    }

    /**
     * The checks that build what the configuration names are not run: the
     * settings naming any are listed as checked at boot, and nothing they name
     * is resolved.
     *
     * @return void
     */
    public function testTheChecksThatBuildAreLeftToTheBoot(): void
    {
        $findings = $this->check([
            ...$this->authorizationConfig(),
            'context'    => ['keys' => [], 'sources' => [PlanContextSource::class]],
            'attributes' => ['resources' => ['post' => RecordingResourceAttributes::class], 'subjects' => []],
            'session'    => ['scopes' => ['posts.read']],
            'cache'      => ['store' => 'array'],
        ]);

        self::assertSame([], $findings->issues);
        self::assertSame([
            'authorization.cache.store',
            'authorization.context.sources',
            'authorization.attributes.resources',
            'authorization.session.scopes',
        ], $findings->checkedAtBoot);
        self::assertFalse($this->container()->resolved(PlanContextSource::class));
        self::assertFalse($this->container()->resolved(RecordingResourceAttributes::class));
    }

    /**
     * Return the value no issue may hold.
     *
     * @return string
     */
    public static function secret(): string
    {
        return self::SECRET;
    }

    /**
     * Check the configuration in the suite's application.
     *
     * @param  mixed  $root
     * @return \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings
     */
    private function check(mixed $root): ConfigFindings
    {
        return (new StructuralCheck($this->container()))->run($root);
    }

    /**
     * Return the path and code of each issue, in order.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings  $findings
     * @return list<array{string, string}>
     */
    private static function pathsAndCodes(ConfigFindings $findings): array
    {
        return \array_map(static fn (ConfigIssue $issue): array => [$issue->path, $issue->code->value], $findings->issues);
    }
}
