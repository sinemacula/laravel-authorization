<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Psr\Log\AbstractLogger;

/**
 * A logger that records what it is given, bound as `log` so the package's log
 * helper writes to it directly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingLogger extends AbstractLogger
{
    /** @var list<array{level: string, message: string, context: array<mixed>}> */
    public array $records = [];

    /**
     * @param  mixed  $level
     * @param  string|\Stringable  $message
     * @param  array<mixed>  $context
     * @return void
     */
    #[\Override]
    public function log(mixed $level, string|\Stringable $message, array $context = []): void
    {
        $this->records[] = ['level' => \is_string($level) ? $level : '', 'message' => (string) $message, 'context' => $context];
    }

    /**
     * Return the messages recorded.
     *
     * @return list<string>
     */
    public function messages(): array
    {
        return \array_column($this->records, 'message');
    }
}
