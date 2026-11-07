<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use SineMacula\Laravel\Authorization\Subject;

/**
 * What every class of one query's rows is decided for: the model queried, the
 * subject, the action, the caller's context, the screen that compiles each
 * statement and keeps the refusals, and the reader of the policies attached to
 * records, if any.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClassRequest
{
    /**
     * Create the request every class is decided for.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Query\StatementScreen  $screen
     * @param  \SineMacula\Laravel\Authorization\Query\RecordAttachments|null  $attachments
     */
    public function __construct(

        /** The model queried. */
        public ResourceShape $shape,

        /** The subject the query is scoped for. */
        public Subject $subject,

        /** The action the query is scoped to. */
        public string $action,

        /** The caller's context. */
        public array $context,

        /** Compiles each statement, keeping the refusals. */
        public StatementScreen $screen,

        /** Reads the policies attached to records; null when the pipeline reads none. */
        public ?RecordAttachments $attachments = null,
    ) {}
}
