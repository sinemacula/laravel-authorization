<?php

declare(strict_types = 1);

namespace Tests\Unit\Console\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Console\Support\ReportText;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigurationReport;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingRow;

/**
 * Unit tests for the configuration report as `authorization:check` prints it as
 * text.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReportText::class)]
final class ReportTextTest extends TestCase
{
    /**
     * A refusal, a skipped check and an unforeseen failure are each told on a
     * line of their own, before any section, and the last line tells the
     * outcome.
     *
     * @return void
     */
    public function testEachIssueIsToldFirst(): void
    {
        $lines = ReportText::lines(self::report(issues: [
            new ConfigIssue('authorization.bulk.chunk_size', IssueCode::OUT_OF_RANGE, 'a whole number of at least 1', 'int'),
            ConfigIssue::skipped('authorization.attributes.resources', 'authorization.models.role'),
            ConfigIssue::internal('authorization.context.sources', new \TypeError('hidden')),
            ConfigIssue::internal('report.seams', new \RuntimeException('hidden')),
            new ConfigIssue('authorization', IssueCode::INVALID_TYPE, 'an array', 'string'),
        ]));

        self::assertSame([
            '<error>[setting authorization.bulk.chunk_size]</error> out of range; expected a whole number of at least 1; found int',
            '<comment>[setting authorization.attributes.resources]</comment> skipped; it depends on authorization.models.role, which was refused',
            '<error>[setting authorization.context.sources]</error> could not be completed (TypeError)',
            '<error>[check report.seams]</error> could not be completed (RuntimeException)',
            '<error>[setting authorization]</error> invalid type; expected an array; found string',
            '',
            '<comment>Settings</comment>',
        ], \array_slice($lines, 0, 7));
        self::assertSame('A check failed.', $lines[\count($lines) - 1]);
        self::assertSame('The check could not be completed.', self::last(ReportText::lines(self::report(issues: [ConfigIssue::internal('report.seams', new \RuntimeException)]))));
        self::assertSame('Every check passed.', self::last(ReportText::lines(self::report())));
    }

    /**
     * A setting is told by its status, then its value where it is shown, its
     * type where it is not, or that it is not set.
     *
     * @return void
     */
    public function testEachSettingIsToldWithItsValueOrType(): void
    {
        $lines = ReportText::lines(self::report(settings: [
            new SettingRow('authorization.models.role', true, true, ['App\Role'], 'string', 'ok'),
            new SettingRow('authorization.gate.enabled', true, true, [false], 'bool', 'refused'),
            new SettingRow('authorization.bulk.chunk_size', true, true, [500], 'int', 'skipped'),
            new SettingRow('authorization.connection', true, true, [null], 'null', 'unchecked'),
            new SettingRow('authorization.context.sources', true, true, [['App\One', 'App\Two']], 'array(2)', 'checked_at_boot'),
            new SettingRow('authorization.session.scopes', true, true, [['read']], 'array(1)', 'failed_at_boot'),
            new SettingRow('authorization.cache.store', true, true, ['array'], 'string', 'not_run'),
            new SettingRow('authorization.attributes.resources', true, true, [['App\Provider' => 'post']], 'array(1)', 'ok'),
            new SettingRow('authorization.cache.prefix', true, true, null, 'string', 'ok'),
            new SettingRow('authorization.rank.enabled', true, false, null, null, 'ok'),
            new SettingRow('authorization.secret', false, true, null, 'array(3)', 'refused'),
        ]));

        self::assertSame([
            '[setting authorization.models.role] ok; App\Role',
            '[setting authorization.gate.enabled] refused; false',
            '[setting authorization.bulk.chunk_size] skipped; 500',
            '[setting authorization.connection] not checked; null',
            '[setting authorization.context.sources] checked at boot; [App\One, App\Two]',
            '[setting authorization.session.scopes] failed at boot; [read]',
            '[setting authorization.cache.store] not run at boot; array',
            '[setting authorization.attributes.resources] ok; [App\Provider => post]',
            '[setting authorization.cache.prefix] ok; value not shown (string)',
            '[setting authorization.rank.enabled] ok; not set, so its default applies',
            '[setting authorization.secret] refused; unknown key; value not shown (array(3))',
        ], \array_slice($lines, 2, 11));
    }

    /**
     * The grant hooks are told in the order they run: a listed hook by its
     * class, or its type when its value is not shown, then the bound hook,
     * noting that the package's own runs no hook of its own.
     *
     * @return void
     */
    public function testTheGrantHooksAreToldInOrder(): void
    {
        $lines = ReportText::lines(self::report(grantHooks: [
            ['position' => 1, 'source' => 'configured', 'class' => 'App\Hook', 'type' => 'string', 'origin' => null, 'factory' => null, 'runs' => true],
            ['position' => 2, 'source' => 'configured', 'class' => null, 'type' => 'int', 'origin' => null, 'factory' => null, 'runs' => true],
            ['position' => 3, 'source' => 'bound', 'class' => 'Package\Hooks', 'type' => null, 'origin' => 'package_default', 'factory' => null, 'runs' => false],
        ]));
        $later = ReportText::lines(self::report(grantHooks: [
            ['position' => 1, 'source' => 'bound', 'class' => null, 'type' => null, 'origin' => 'later_binding', 'factory' => 'app/Hook.php:4', 'runs' => true],
        ]));

        self::assertSame([
            '<comment>Grant hooks, in the order they run; the chain stops at the first refusal</comment>',
            '[grant hook 1] App\Hook; listed in authorization.grant_hooks',
            '[grant hook 2] value not shown (int); listed in authorization.grant_hooks',
            '[grant hook 3] Package\Hooks; bound to the contract, package default; runs no hook of its own',
        ], \array_slice($lines, 5, 4));
        self::assertSame('[grant hook 1] supplied by custom code (app/Hook.php:4); class decided at first use; bound to the contract, later binding', $later[6]);
    }

    /**
     * The connection is told by names, the setting each was chosen by and
     * drivers alone, the database never connected to.
     *
     * @return void
     */
    public function testTheConnectionIsToldByNameAndDriver(): void
    {
        $lines = ReportText::lines(self::report(connection: [
            'database' => ['name' => 'audit', 'chosen' => 'configured', 'driver' => 'pgsql', 'connectivity' => 'not_tested'],
            'cache'    => ['store' => 'shared', 'chosen' => 'configured', 'driver' => null],
            'queue'    => ['connection' => 'jobs', 'chosen' => 'default', 'driver' => 'redis', 'queue' => 'usage'],
        ]));
        $none = ReportText::lines(self::report(connection: [
            'database' => ['name' => null, 'chosen' => 'default', 'driver' => null, 'connectivity' => 'not_tested'],
            'cache'    => ['store' => null, 'chosen' => 'none', 'driver' => null],
            'queue'    => ['connection' => 'sync', 'chosen' => 'default', 'driver' => 'sync', 'queue' => null],
        ]));

        self::assertSame([
            '[connection database] audit; chosen by authorization.connection; driver pgsql; not connected to',
            '[connection cache] shared; chosen by authorization.cache.store; driver unknown',
            '[connection queue] jobs; chosen by queue.default; driver redis; queue usage',
        ], \array_slice($lines, 8, 3));
        self::assertSame([
            '[connection database] none',
            '[connection cache] none (entries are kept for the request or job alone)',
            '[connection queue] sync; chosen by queue.default; driver sync; queue the default',
        ], \array_slice($none, 8, 3));
    }

    /**
     * A name or a driver the report withheld, as it is not a name, is told as
     * not shown, never as none or the default; a part that could not be read is
     * told as none.
     *
     * @return void
     */
    public function testAWithheldNameIsToldAsNotShown(): void
    {
        $lines = ReportText::lines(self::report(connection: [
            'database' => ['name' => null, 'chosen' => 'configured', 'driver' => null, 'connectivity' => 'not_tested', 'redacted' => ['name', 'driver']],
            'cache'    => null,
            'queue'    => ['connection' => 'jobs', 'chosen' => 'configured', 'driver' => 'sqs', 'queue' => null, 'redacted' => ['queue']],
        ]));

        self::assertSame([
            '[connection database] value not shown; chosen by authorization.connection; driver value not shown; not connected to',
            '[connection cache] none (entries are kept for the request or job alone)',
            '[connection queue] jobs; chosen by authorization.usage.connection; driver sqs; queue value not shown',
        ], \array_slice($lines, 8, 3));
    }

    /**
     * Each integration is told by its state, the Gate hook in words, and a
     * middleware alias bound to something else names it.
     *
     * @return void
     */
    public function testEachIntegrationIsTold(): void
    {
        $lines = ReportText::lines(self::report(integrations: [
            ['name' => 'gate', 'state' => 'not_registered', 'detail' => null],
            ['name' => 'blade_directives', 'state' => 'partly_registered', 'detail' => null],
            ['name' => 'middleware.role', 'state' => 'other', 'detail' => 'App\<Role>'],
        ]));

        self::assertSame([
            '[integration gate] not registered (authorization.gate.enabled is on, but the hook is not in place)',
            '[integration blade_directives] partly registered',
            '[integration middleware.role] other (App\\\<Role\>)',
        ], \array_slice($lines, 13, 3));
    }

    /**
     * A name is escaped: its console markup, its control, format and
     * bidirectional characters, or all of it when it is not UTF-8.
     *
     * @return void
     */
    public function testNamesAreEscaped(): void
    {
        self::assertSame('\<error\>x\u001b\u202e', ReportText::escape("<error>x\e\u{202E}"));
        self::assertSame('\ufffd', ReportText::escape("\xff"));
        self::assertSame('<info>[a\<b\>]</info> state', ReportText::line('a<b>', 'state', 'info'));
    }

    /**
     * Return the last line.
     *
     * @param  list<string>  $lines
     * @return string|null
     */
    private static function last(array $lines): ?string
    {
        return $lines[\count($lines) - 1] ?? null;
    }

    /**
     * Return a report holding the parts given and nothing else.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingRow>  $settings
     * @param  list<array<string, mixed>>  $grantHooks
     * @param  array<string, mixed>  $connection
     * @param  list<array{name: string, state: string, detail: string|null}>  $integrations
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue>  $issues
     * @return \SineMacula\Laravel\Authorization\Diagnostics\ConfigurationReport
     */
    private static function report(array $settings = [], array $grantHooks = [], array $connection = [], array $integrations = [], array $issues = []): ConfigurationReport
    {
        return new ConfigurationReport($settings, [], $grantHooks, $connection, $integrations, $issues);
    }
}
