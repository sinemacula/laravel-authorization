<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Log;
use Monolog\Handler\TestHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Log\AbstractLogger;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;
use Tests\TestCase;

/**
 * Feature tests for `AuthorizationLog`, run against Laravel's real log manager.
 *
 * Lines go to the channel named by `authorization.log_channel`, or to the
 * default channel when it names none or names a channel that does not exist,
 * and never to the emergency logger.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationLog::class)]
final class AuthorizationLogTest extends TestCase
{
    /**
     * Set up a default and a named channel, each writing to a test handler.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'logging.default'                  => 'default-capture',
            'logging.channels.default-capture' => ['driver' => 'monolog', 'handler' => TestHandler::class],
            'logging.channels.audit-capture'   => ['driver' => 'monolog', 'handler' => TestHandler::class],
        ]);

        Log::forgetChannel('default-capture');
        Log::forgetChannel('audit-capture');
    }

    /**
     * With no channel configured, a warning goes to the default channel and no
     * emergency line is written.
     *
     * @return void
     */
    public function testWarningGoesToTheDefaultChannelWhenNoneIsConfigured(): void
    {
        config(['authorization.log_channel' => null]);

        AuthorizationLog::warning('gate conflict', ['permission' => 'posts:create']);

        self::assertTrue($this->handler('default-capture')->hasWarningThatContains('gate conflict'));
        self::assertSame(['permission' => 'posts:create'], $this->handler('default-capture')->getRecords()[0]->context);
        self::assertFalse($this->handler('default-capture')->hasEmergencyRecords());
        self::assertFalse($this->handler('audit-capture')->hasRecords('warning'));
    }

    /**
     * A configured channel that exists receives the warning; the default does
     * not.
     *
     * @return void
     */
    public function testWarningGoesToTheConfiguredChannel(): void
    {
        config(['authorization.log_channel' => 'audit-capture']);

        AuthorizationLog::warning('gate conflict');

        self::assertTrue($this->handler('audit-capture')->hasWarningThatContains('gate conflict'));
        self::assertFalse($this->handler('default-capture')->hasRecords('warning'));
    }

    /**
     * A configured channel that is not defined falls back to the default
     * channel rather than to the emergency logger.
     *
     * @return void
     */
    public function testUndefinedChannelFallsBackToTheDefaultChannel(): void
    {
        config(['authorization.log_channel' => 'authorization']);

        AuthorizationLog::warning('gate conflict');

        self::assertTrue($this->handler('default-capture')->hasWarningThatContains('gate conflict'));
        self::assertFalse($this->handler('default-capture')->hasEmergencyRecords());
    }

    /**
     * An empty channel name is treated as none.
     *
     * @return void
     */
    public function testEmptyChannelNameUsesTheDefaultChannel(): void
    {
        config(['authorization.log_channel' => '']);

        AuthorizationLog::warning('gate conflict');

        self::assertTrue($this->handler('default-capture')->hasWarningThatContains('gate conflict'));
    }

    /**
     * Debug lines follow the same routing, at debug level.
     *
     * @return void
     */
    public function testDebugLinesAreWrittenAtDebugLevel(): void
    {
        config(['authorization.log_channel' => 'audit-capture']);

        AuthorizationLog::debug('unknown operator', ['operator' => 'bogus']);

        self::assertTrue($this->handler('audit-capture')->hasDebugThatContains('unknown operator'));
        self::assertFalse($this->handler('audit-capture')->hasRecords('warning'));
        self::assertSame(['operator' => 'bogus'], $this->handler('audit-capture')->getRecords()[0]->context);
    }

    /**
     * A logger that is not Laravel's log manager is written to directly.
     *
     * @return void
     */
    public function testOtherLoggersAreWrittenToDirectly(): void
    {
        $logger = new class extends AbstractLogger {
            /** @var list<array{0: mixed, 1: string}> */
            public array $lines = [];

            /**
             * Record a line.
             *
             * @param  mixed  $level
             * @param  string|\Stringable  $message
             * @param  array<array-key, mixed>  $context
             * @return void
             */
            #[\Override]
            public function log(mixed $level, string|\Stringable $message, array $context = []): void
            {
                $this->lines[] = [$level, (string) $message];
            }
        };

        $this->app?->instance('log', $logger);

        AuthorizationLog::warning('gate conflict');
        AuthorizationLog::debug('unknown operator');

        self::assertSame([['warning', 'gate conflict'], ['debug', 'unknown operator']], $logger->lines);
    }

    /**
     * A logger that fails never aborts the caller.
     *
     * @return void
     */
    public function testFailingLoggerIsIgnored(): void
    {
        $this->app?->instance('log', new class extends AbstractLogger {
            /**
             * Fail on every line.
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
                throw new \RuntimeException('log unavailable');
            }
        });

        AuthorizationLog::warning('gate conflict');
        AuthorizationLog::debug('unknown operator');

        self::addToAssertionCount(1);
    }

    /**
     * Return the test handler behind a capture channel.
     *
     * @param  string  $channel
     * @return \Monolog\Handler\TestHandler
     */
    private function handler(string $channel): TestHandler
    {
        /** @var \Illuminate\Log\Logger $logger */
        $logger = Log::channel($channel);

        /** @var \Monolog\Logger $monolog */
        $monolog = $logger->getLogger();

        $handler = $monolog->getHandlers()[0];

        self::assertInstanceOf(TestHandler::class, $handler);

        return $handler;
    }
}
