<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

/**
 * Read each part of the configuration report on its own, so a part that cannot
 * be read leaves the rest of the report whole: the part is replaced by its
 * fallback, and an `internal` issue naming it, with the exception's class
 * alone, makes the report incomplete.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReportParts
{
    /** @var list<\SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue> An issue for each part that could not be read. */
    private array $failures = [];

    /**
     * Return what the reader reads, or the fallback when it throws.
     *
     * @template TPart
     *
     * @param  string  $part
     * @param  \Closure(): TPart  $reader
     * @param  TPart  $fallback
     * @return TPart
     */
    public function read(string $part, \Closure $reader, mixed $fallback): mixed
    {
        try {
            return $reader();
        } catch (\Throwable $exception) {
            $this->failures[] = ConfigIssue::internal("report.{$part}", $exception);

            return $fallback;
        }
    }

    /**
     * Return an issue for each part that could not be read.
     *
     * @return list<\SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue>
     */
    public function failures(): array
    {
        return $this->failures;
    }
}
