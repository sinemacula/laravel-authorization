<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Console\Kernel;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Console\Concerns\RefusesInvocations;
use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Tester\CommandTester;
use Tests\TestCase;

/**
 * Feature tests for how the console commands refuse what they cannot run: an
 * invocation the console cannot bind and an option given without its value exit
 * 2, on the standard error alone, the error escaped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(RefusesInvocations::class)]
final class RefusesInvocationsTest extends TestCase
{
    /**
     * Both commands refuse an unknown option and a missing argument as an
     * invalid invocation, writing nothing to the standard output.
     *
     * @return void
     */
    public function testAnInvocationTheConsoleCannotBindExitsTwo(): void
    {
        foreach (['authorization:why' => ['subject' => 'user:1', 'action' => 'a'], 'authorization:review' => ['query' => 'holders']] as $command => $parameters) {
            $tester = $this->tester($command);

            self::assertSame(2, $tester->execute([...$parameters, '--unknown' => 'x'], ['capture_stderr_separately' => true]), $command);
            self::assertSame('', $tester->getDisplay(), $command);
            self::assertSame("The \"--unknown\" option does not exist.\n", $tester->getErrorOutput(), $command);

            self::assertSame(2, $tester->execute([], ['capture_stderr_separately' => true]), $command);
            self::assertStringStartsWith('Not enough arguments', $tester->getErrorOutput(), $command);
        }
    }

    /**
     * An option that takes a value but is given none is refused, naming the
     * option, rather than read as if it were omitted.
     *
     * @return void
     */
    public function testAnOptionGivenWithoutItsValueIsRefused(): void
    {
        $kernel = $this->app?->make(Kernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);

        $lines = [
            'authorization:why user:1 a --tenant'          => 'tenant',
            'authorization:review expiring --from'         => 'from',
            'authorization:review holders role:1 --output' => 'output',
        ];

        foreach ($lines as $line => $option) {
            $output = new BufferedOutput;

            self::assertSame(2, $kernel->handle(new StringInput($line), $output), $line);
            self::assertStringContainsString("The --{$option} option must be given a value.", $output->fetch(), $line);
        }
    }

    /**
     * Markup and control characters in an error are escaped, so neither styles
     * nor moves the terminal.
     *
     * @return void
     */
    public function testAnErrorIsEscaped(): void
    {
        $tester = $this->tester('authorization:review');

        $tester->execute(['query' => 'holdings', 'reference' => "<fg=red>evil\e[2J\u{85}</>:1"], ['capture_stderr_separately' => true, 'decorated' => true]);

        $errors = $tester->getErrorOutput();

        self::assertStringContainsString('\'<fg=red>evil\u001b[2J\u0085</>\'', $errors);
        self::assertStringNotContainsString("\e[31m", $errors);
        self::assertStringNotContainsString("\e[2J", $errors);
        self::assertStringNotContainsString("\u{85}", $errors);
        self::assertStringStartsWith("\e[37;41m", $errors);
    }

    /**
     * Return a tester for the registered command.
     *
     * @param  string  $command
     * @return \Symfony\Component\Console\Tester\CommandTester
     */
    private function tester(string $command): CommandTester
    {
        $kernel = $this->app?->make(Kernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);

        return new CommandTester($kernel->all()[$command]);
    }
}
