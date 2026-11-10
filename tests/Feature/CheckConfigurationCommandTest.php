<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\CheckConfigurationCommand;
use Tests\TestCase;

/**
 * Feature tests for `authorization:check`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckConfigurationCommand::class)]
final class CheckConfigurationCommandTest extends TestCase
{
    /** @var string The line reporting the Gate hook enabled. */
    private const string ENABLED = 'Gate hook: enabled (the package answers every ability it declares through Gate::before)';

    /** @var string The line reporting the Gate hook disabled. */
    private const string DISABLED = 'Gate hook: disabled (authorization.gate.enabled is false; Laravel decides every ability)';

    /**
     * The command is registered under its `NAME` constant, the name its
     * signature declares.
     *
     * @return void
     */
    public function testTheCommandsNameIsItsConstant(): void
    {
        self::assertSame('authorization:check', CheckConfigurationCommand::NAME);
        self::assertInstanceOf(CheckConfigurationCommand::class, Artisan::all()[CheckConfigurationCommand::NAME] ?? null);
        self::assertSame(CheckConfigurationCommand::NAME, Artisan::all()[CheckConfigurationCommand::NAME]->getName());
    }

    /**
     * With the shipped configuration the command reports the Gate hook enabled,
     * one line per check, and succeeds.
     *
     * @return void
     */
    public function testReportsTheGateHookEnabledByDefault(): void
    {
        self::assertSame(0, Artisan::call('authorization:check'));
        self::assertSame([self::ENABLED], $this->lines());
    }

    /**
     * With the switch off the command reports the Gate hook disabled, and still
     * succeeds.
     *
     * @return void
     */
    public function testReportsTheGateHookDisabled(): void
    {
        config(['authorization.gate.enabled' => false]);

        self::assertSame(0, Artisan::call('authorization:check'));
        self::assertSame([self::DISABLED], $this->lines());
    }

    /**
     * A `gate` block without the switch reports the Gate hook enabled, as the
     * switch is on unless it is false.
     *
     * @return void
     */
    public function testReportsTheGateHookEnabledWithoutTheSwitch(): void
    {
        config(['authorization.gate' => []]);

        self::assertSame(0, Artisan::call('authorization:check'));
        self::assertSame([self::ENABLED], $this->lines());
    }

    /**
     * Return each line the last command wrote.
     *
     * @return list<string>
     */
    private function lines(): array
    {
        return \array_values(\array_filter(\explode("\n", Artisan::output()), static fn (string $line): bool => $line !== ''));
    }
}
