<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider;

/**
 * A subject attribute provider declaring a department, which records every
 * subject it is asked about and returns a key it does not declare beside the
 * one it does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingSubjectAttributes implements SubjectAttributeProvider
{
    /** @var list<object> Each subject asked about. */
    public array $calls = [];

    /**
     * Return the attributes the provider declares.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>
     */
    #[\Override]
    public function attributes(): array
    {
        return ['department' => 'string'];
    }

    /**
     * Return the subject's attributes, recording the call.
     *
     * @param  object  $subject
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(object $subject): array
    {
        $this->calls[] = $subject;

        return ['department' => 'sales', 'salary' => 90000];
    }
}
