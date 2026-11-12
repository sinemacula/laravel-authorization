<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Container\Container;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;

/**
 * Asserts that a delegated call to a management service is refused, as the
 * decision of its administration action refuses it, before anything is written:
 * every table a management service writes is left as it was, and no change
 * event is dispatched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 */
trait AssertsDelegatedRefusals
{
    /**
     * Assert the call is refused with an `AuthorizationException` for the
     * reason, writing nothing and dispatching no change event, and return the
     * refusal. The package's events are faked from then on (see
     * `fakePackageEvents()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     *
     * @throws \JsonException
     */
    protected static function assertDelegatedRefusal(DecisionReason $reason, \Closure $call): AuthorizationException
    {
        self::fakePackageEvents();

        $before  = self::writtenRows();
        $refusal = null;

        try {
            $call();
        } catch (AuthorizationException $exception) {
            $refusal = $exception;
        }

        self::assertInstanceOf(AuthorizationException::class, $refusal, 'The call was not refused.');
        self::assertSame($reason, $refusal->getReason());
        self::assertSame($before, self::writtenRows());
        self::assertSame([], self::changesDispatched());

        return $refusal;
    }

    /**
     * Fake the package's events, and those alone, so the models' own still run
     * their observers, recording them from now on, the decisions included: the
     * authorization manager is made afresh, with the faked dispatcher.
     *
     * @return void
     */
    protected static function fakePackageEvents(): void
    {
        Event::fake([static fn (string $name): bool => \is_subclass_of($name, AuthorizationEvent::class)]);

        Container::getInstance()->forgetInstance('authorization');
    }

    /**
     * Return the package events dispatched since they were faked, but the
     * decisions and the refusals, by class.
     *
     * @return list<string>
     */
    protected static function changesDispatched(): array
    {
        /** @var array<string, list<array{0: object}>> $dispatched */
        $dispatched = Event::dispatchedEvents(); // @phpstan-ignore staticMethod.notFound
        $changes    = [];

        foreach ($dispatched as $calls) {
            foreach ($calls as [$event]) {
                if (!$event instanceof AuthorizationEvent || $event instanceof DecisionEvaluated || $event instanceof AuthorizationFailed) {
                    continue;
                }

                $changes[] = $event::class;
            }
        }

        return $changes;
    }

    /**
     * Return the actions decided since the package's events were faked, in
     * order.
     *
     * @return list<string>
     */
    protected static function actionsDecided(): array
    {
        $actions = [];

        foreach (Event::dispatched(DecisionEvaluated::class)->all() as $call) {
            $event = \is_array($call) ? $call[0] ?? null : null;

            if (!$event instanceof DecisionEvaluated) {
                continue;
            }

            $actions[] = $event->action;
        }

        return $actions;
    }

    /**
     * Return every row of every table a management service writes, each as
     * JSON, sorted, to tell whether anything was written.
     *
     * @return array<string, list<string>>
     *
     * @throws \JsonException
     */
    private static function writtenRows(): array
    {
        $tables = [
            'roles', 'permissions', 'policies', 'role_permissions', 'authorizable_roles', 'authorizable_permissions', 'authorizable_policies',
            'authorizable_boundaries', 'resource_policies', 'guardrails', 'role_exclusions',
        ];
        $rows = [];

        foreach ($tables as $table) {
            $encoded = [];

            foreach (DB::table($table)->get() as $row) {
                $encoded[] = \json_encode((array) $row, \JSON_THROW_ON_ERROR);
            }

            \sort($encoded);

            $rows[$table] = $encoded;
        }

        return $rows;
    }
}
