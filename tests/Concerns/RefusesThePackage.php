<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Events\QueryExecuted;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Has the package of the test's application refuse, as a diagnostic boot that
 * found an unknown setting would, and asserts that operations refuse there,
 * each in the method that guards it, before it delegates to another, and before
 * any query runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait RefusesThePackage
{
    /** @var string The setting the refusal names. */
    protected const string REFUSED_SETTING = 'authorization.nonsense';

    /** @var list<string> The queries run since the package refused. */
    private array $refusedQueries = [];

    /**
     * Have the package refuse with what the structural check finds in its
     * configuration with an unknown setting, and count every query run from
     * then on.
     *
     * @return void
     */
    protected function refuseThePackage(): void
    {
        $app      = $this->container();
        $findings = ConfigValidator::issues([...$this->authorizationConfig(), 'nonsense' => true], $app);

        PackageState::of($app)?->refuse($findings);

        $app['events']->listen(QueryExecuted::class, function (QueryExecuted $query): void {
            $this->refusedQueries[] = $query->sql;
        });
    }

    /**
     * Assert that each operation refuses, naming the setting refused, refused
     * by the function its name starts with, and that no query ran since the
     * package refused.
     *
     * @param  array<string, \Closure(): mixed>  $operations
     * @return void
     */
    protected function assertEachRefused(array $operations): void
    {
        foreach ($operations as $name => $operation) {
            $refusal = self::packageRefusalOf($operation, $name);

            self::assertSame(self::REFUSED_SETTING, $refusal->getConfigKey(), $name);
            self::assertSame(\explode(' ', $name)[0], self::guardedBy($refusal), $name);
        }

        self::assertSame([], $this->refusedQueries);
    }

    /**
     * Return the function that asked whether the package may run when the
     * refusal was thrown, the first outside the state itself, any closure read
     * as `{closure}`.
     *
     * @param  \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException  $refusal
     * @return string
     */
    protected static function guardedBy(InvalidAuthorizationConfigException $refusal): string
    {
        foreach ($refusal->getTrace() as $frame) {
            if (($frame['class'] ?? null) !== PackageState::class) {
                return \str_contains($frame['function'], '{closure') ? '{closure}' : $frame['function'];
            }
        }

        self::fail('The refusal was not thrown by the package state.');
    }

    /**
     * Return the refusal the operation throws, found among the exceptions a
     * caller wraps it in.
     *
     * @param  \Closure(): mixed  $operation
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     *
     * @throws \Throwable
     */
    protected static function packageRefusalOf(\Closure $operation, string $name = 'the operation'): InvalidAuthorizationConfigException
    {
        try {
            $operation();
        } catch (\Throwable $thrown) {
            for ($exception = $thrown; $exception !== null; $exception = $exception->getPrevious()) {
                if ($exception instanceof InvalidAuthorizationConfigException) {
                    return $exception;
                }
            }

            throw $thrown;
        }

        self::fail("{$name} was not refused.");
    }
}
