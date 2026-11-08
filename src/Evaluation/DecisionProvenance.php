<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Who a decision was about, who previewed it, and where it was made, as
 * references (AUTHZ-15.3, AUTHZ-15.5).
 *
 * The subject is the principal the decision was about and the identity the
 * person or machine behind it, each null when the decision had no subject, as a
 * guest's has none, or when it is no saved record; neither is ever filled from
 * the authenticated user. The previewer is whoever previewed the decision as
 * the subject, and null for any decision that is not a preview. The tenant and
 * the application are those of the subject the decision was made for, so a
 * decision with no subject names neither.
 *
 * It holds references and names alone, never a model, a session or a value, so
 * it is safe to log or store. The last decision is kept with it, which
 * `Authorization::lastDecisionProvenance()` returns, and the decision events
 * carry the same fields.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DecisionProvenance
{
    /**
     * Create a new decision provenance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $identity
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $previewer
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     */
    public function __construct(

        /** The principal the decision was about; null when it had none, or none that is a saved record. */
        public ?Reference $subject = null,

        /** The identity behind the principal; null when it had none, or none that is a saved record. */
        public ?Reference $identity = null,

        /** Whoever previewed the decision as the subject; null for a decision that is not a preview. */
        public ?Reference $previewer = null,

        /** The tenant the decision was made in; null for none. */
        public ?Reference $tenant = null,

        /** The application the decision was made in; null for none. */
        public ?string $application = null,
    ) {}

    /**
     * Return the provenance of a decision about the subject, null for none,
     * previewed by the previewer, null for a decision that is not a preview.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $previewer
     * @return self
     */
    public static function of(?Subject $subject, ?Reference $previewer = null): self
    {
        return new self(
            self::referenceTo($subject?->subject),
            self::referenceTo($subject?->identity),
            $previewer,
            self::referenceTo($subject?->tenant),
            $subject?->application,
        );
    }

    /**
     * Determine whether the decision is a preview: someone previewed it as the
     * subject.
     *
     * @return bool
     */
    public function isPreview(): bool
    {
        return $this->previewer !== null;
    }

    /**
     * Return the reference to the record, by its morph class and key, or null
     * for none, for an object that is neither a model nor a tenant, or for one
     * with no key.
     *
     * @param  object|null  $record
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    private static function referenceTo(?object $record): ?Reference
    {
        if (!$record instanceof Model && !$record instanceof AuthorizableTenant) {
            return null;
        }

        $key = $record->getKey();
        $id  = \is_scalar($key) ? (string) $key : '';

        return $id === '' ? null : new Reference($record->getMorphClass(), $id);
    }
}
