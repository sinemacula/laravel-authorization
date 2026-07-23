<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Psr\Log\AbstractLogger;

/**
 * Fake logger whose `channel()` always raises — drives the default-channel
 * fallback path in authorization loggers.
 *
 * The trait / cache layer calls `logger()->channel('authorization')` first, and
 * on failure falls back to `logger()->warning(...)` on the default channel.
 * This stub records the call counts, the last message, and the last context so
 * assertions can pin the fallback branch ran and the emitted payload stays
 * honest against mutation-kill flags.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S112")
 */
final class ChannelThrowingLogger extends AbstractLogger
{
    /** @var int */
    public int $channelCalls = 0;

    /** @var int */
    public int $warningCalls = 0;

    /** @var string|null */
    public ?string $lastMessage = null;

    /** @var array<string, mixed>|null */
    public ?array $lastContext = null;

    /**
     * @param  string  $name
     * @return never
     *
     * @throws \RuntimeException
     */
    public function channel(string $name): never
    {
        $this->channelCalls++;

        throw new \RuntimeException('channel ' . $name . ' is unavailable');
    }

    /**
     * @param  string|\Stringable  $message
     * @param  array<mixed>  $context
     * @return void
     */
    #[\Override]
    public function warning(string|\Stringable $message, array $context = []): void
    {
        $this->warningCalls++;
        $this->lastMessage = (string) $message;
        $this->lastContext = $context; // @phpstan-ignore assign.propertyType
    }

    /**
     * @param  mixed  $level
     * @param  string|\Stringable  $message
     * @param  array<mixed>  $context
     * @return void
     */
    #[\Override]
    public function log(mixed $level, string|\Stringable $message, array $context = []): void {}
}
