<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A console subject resolver an application binds: it resolves every reference
 * to one subject, as given, or throws the failure it is given, recording each
 * reference it is handed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FixedConsoleSubjectResolver implements ConsoleSubjectResolver
{
    /** @var list<string> Each reference it was handed, in order. */
    public array $references = [];

    /**
     * Create a new resolver instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \Throwable|null  $failure
     */
    public function __construct(

        /** The subject every reference resolves to. */
        private readonly Subject $subject,

        /** What it throws for every reference instead, or null to resolve them. */
        private readonly ?\Throwable $failure = null,
    ) {}

    /**
     * Record the reference and return the fixed subject, or throw the failure.
     *
     * @param  string  $reference
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \Throwable
     */
    #[\Override]
    public function resolve(string $reference): Subject
    {
        $this->references[] = $reference;

        return $this->failure === null ? $this->subject : throw $this->failure;
    }
}
