<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Reviews;

/**
 * A stream wrapper that takes one byte of each write, appending it to the file
 * its URL names, or, for a URL naming no file, takes nothing at all, so a test
 * sees how a writer copes with a stream that writes only part of what it is
 * given. PHP names a stream wrapper's methods, so they are not in camel caps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpcs:disable PSR1.Methods.CamelCapsMethodName.NotCamelCaps
 *
 * @phpcs:disable Squiz.NamingConventions.ValidFunctionName.ScopeNotCamelCaps
 *
 * @phpcs:disable SineMacula.NamingConventions.BooleanMethodName.NotPredicate
 */
final class TrickleStream
{
    /** @var resource|null The context the stream was opened with, set by PHP. */
    public mixed $context = null;

    /** @var string The file each byte is appended to; empty to take nothing. */
    private string $file = '';

    /**
     * Open the stream, naming the file from the URL's path.
     *
     * @param  string  $path
     * @param  string  $mode
     * @param  int  $options
     * @param  string|null  $openedPath
     * @return bool
     */
    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        $this->file = (string) \parse_url($path, \PHP_URL_PATH);

        return true;
    }

    /**
     * Take the first byte of the data, or nothing for a stream naming no file.
     *
     * @param  string  $data
     * @return int
     */
    public function stream_write(string $data): int
    {
        if ($this->file === '' || $this->file === '/') {
            return 0;
        }

        \file_put_contents($this->file, $data[0], \FILE_APPEND);

        return 1;
    }
}
