<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Diagnostics\Checks\ExtensionChecks;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\IssueCollector;
use Tests\Feature\Stubs\FailingContextSource;
use Tests\Feature\Stubs\PlanContextSource;
use Tests\Feature\Stubs\RecordingSubjectAttributes;
use Tests\TestCase;

/**
 * Feature tests for the structural checks of the settings naming extension
 * code, which build nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExtensionChecks::class)]
final class ExtensionChecksTest extends TestCase
{
    /**
     * Each entry is checked on its own; the catalogue's check of the context
     * keys runs only once every namespace passed.
     *
     * @return void
     */
    public function testEachEntryIsCheckedOnItsOwn(): void
    {
        $findings = $this->check([
            'context'    => ['keys' => ['tenant' => ['plan' => 3], 'ok' => ['a' => 'string']], 'sources' => ['Missing\Source', PlanContextSource::class]],
            'attributes' => ['resources' => ['' => PlanContextSource::class, 'post' => PlanContextSource::class], 'subjects' => 'x'],
            'session'    => ['source' => 3, 'scopes' => [['nested']]],
        ]);

        self::assertSame([
            ['authorization.context.keys', 'invalid_value'],
            ['authorization.context.sources.0', 'unknown_class'],
            ['authorization.attributes.resources', 'invalid_value'],
            ['authorization.attributes.resources.post', 'not_implemented'],
            ['authorization.attributes.subjects', 'invalid_type'],
            ['authorization.session.source', 'invalid_type'],
            ['authorization.session.scopes', 'invalid_value'],
        ], self::pathsAndCodes($findings));
        self::assertSame([], $findings->checkedAtBoot);
    }

    /**
     * Keys the catalogue refuses are refused once every namespace passed; a
     * list naming extension code that passed is left to the boot, and nothing
     * it names is built.
     *
     * @return void
     */
    public function testTheBuildingChecksAreLeftToTheBoot(): void
    {
        $findings = $this->check([
            'context'    => ['keys' => ['tenant' => ['plan' => 'no-such-type']], 'sources' => [FailingContextSource::class]],
            'attributes' => ['subjects' => ['user' => RecordingSubjectAttributes::class]],
            'session'    => ['scopes' => ['posts.read']],
        ]);

        self::assertSame([['authorization.context.keys', 'invalid_value']], self::pathsAndCodes($findings));
        self::assertSame(['authorization.context.sources', 'authorization.attributes.subjects', 'authorization.session.scopes'], $findings->checkedAtBoot);
        self::assertFalse($this->container()->resolved(FailingContextSource::class));
    }

    /**
     * A refused block skips each setting it holds.
     *
     * @return void
     */
    public function testARefusedBlockSkipsItsSettings(): void
    {
        self::assertSame([
            ['authorization.session', 'invalid_type'],
            ['authorization.session.source', 'skipped'],
            ['authorization.session.scopes', 'skipped'],
        ], self::pathsAndCodes($this->check(['session' => 'off'])));
    }

    /**
     * Check the suite's configuration with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings
     */
    private function check(array $settings): ConfigFindings
    {
        $collector = new IssueCollector;

        (new ExtensionChecks($collector, [...$this->authorizationConfig(), ...$settings]))->run();

        return $collector->findings();
    }

    /**
     * Return the path and code of each issue found, in order.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings  $findings
     * @return list<array{string, string}>
     */
    private static function pathsAndCodes(ConfigFindings $findings): array
    {
        return \array_map(static fn (ConfigIssue $issue): array => [$issue->path, $issue->code->value], $findings->issues);
    }
}
