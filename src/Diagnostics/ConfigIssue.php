<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * One issue the configuration check found: a setting refused, a check skipped
 * because a setting it depends on was refused, or a check that failed in a way
 * the package did not foresee.
 *
 * An issue is structured, never a message: the path of the setting, a stable
 * code, what the setting expects, written by the package, and the type of the
 * value found. Neither the value nor an exception's message is kept, as a
 * package message may quote the value and one from an extension may hold
 * anything; an unforeseen failure keeps the exception's class alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfigIssue
{
    /**
     * Create a new issue.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode  $code
     * @param  string|null  $expected
     * @param  string|null  $gotType
     * @param  string|null  $dependsOn
     * @param  class-string<\Throwable>|null  $exception
     */
    public function __construct(

        /** The dotted path of the setting the issue is about. */
        public string $path,

        /** The stable code of the issue. */
        public IssueCode $code,

        /** What the setting expects, written by the package, or null when it is not stated. */
        public ?string $expected = null,

        /** The type of the value refused, or null when it is not stated. */
        public ?string $gotType = null,

        /** The path of the refused setting a skipped check depends on, else null. */
        public ?string $dependsOn = null,

        /** The class of the exception an unforeseen failure threw, else null. */
        public ?string $exception = null,
    ) {}

    /**
     * Return the issue a refusal of the configuration states.
     *
     * @param  \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException  $refusal
     * @return self
     */
    public static function refused(InvalidAuthorizationConfigException $refusal): self
    {
        return new self($refusal->getConfigKey(), $refusal->getIssue(), $refusal->getExpected(), $refusal->getGotType());
    }

    /**
     * Return the issue of a check skipped because the setting it depends on was
     * refused.
     *
     * @param  string  $path
     * @param  string  $dependsOn
     * @return self
     */
    public static function skipped(string $path, string $dependsOn): self
    {
        return new self($path, IssueCode::SKIPPED, dependsOn: $dependsOn);
    }

    /**
     * Return the issue of a check that threw what the package did not foresee,
     * keeping the exception's class alone.
     *
     * @param  string  $path
     * @param  \Throwable  $exception
     * @return self
     */
    public static function internal(string $path, \Throwable $exception): self
    {
        return new self($path, IssueCode::INTERNAL, exception: $exception::class);
    }

    /**
     * Return the kind of the issue: `refusal`, `skipped` or `internal`.
     *
     * @return string
     */
    public function kind(): string
    {
        return $this->code->isRefusal() ? 'refusal' : $this->code->value;
    }

    /**
     * Return the issue in the report's versioned shape.
     *
     * @return array{path: string, code: string, kind: string, expected: string|null, got_type: string|null, depends_on: string|null, exception: string|null}
     */
    public function toArray(): array
    {
        return [
            'path'       => $this->path,
            'code'       => $this->code->value,
            'kind'       => $this->kind(),
            'expected'   => $this->expected,
            'got_type'   => $this->gotType,
            'depends_on' => $this->dependsOn,
            'exception'  => $this->exception,
        ];
    }
}
