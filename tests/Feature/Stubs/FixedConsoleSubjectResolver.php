<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A console subject resolver an application binds: it resolves every reference
 * to one subject, as given, recording each reference it is handed.
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
     */
    public function __construct(

        /** The subject every reference resolves to. */
        private readonly Subject $subject,
    ) {}

    /**
     * Record the reference and return the fixed subject.
     *
     * @param  string  $reference
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function resolve(string $reference): Subject
    {
        $this->references[] = $reference;

        return $this->subject;
    }
}
