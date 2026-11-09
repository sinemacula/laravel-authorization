<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * What an explained check asked, as references (AUTHZ-11.5): the action, the
 * resource, who it was about and who previewed it, the scope it was asked in
 * and the scope it was decided in, which differ when a resource of a tenant
 * below the request's is decided in its own tenant, or one admitted from
 * outside at platform scope (see `DecisionProvenance`).
 *
 * It is captured with the decision, as the check is made, never read back from
 * the state around it. It holds references and names alone, never a model, a
 * context, a session or a value.
 *
 * @phpstan-import-type ReferenceArray from \SineMacula\Laravel\Authorization\Evaluation\GrantProvenance
 * @phpstan-import-type ScopeArray from \SineMacula\Laravel\Authorization\Evaluation\GrantProvenance
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExplanationRequest
{
    /**
     * Create a new explanation request.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance  $requested
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance  $decided
     */
    public function __construct(

        /** The action checked. */
        public string $action,

        /** The resource checked, by its identifier; null for none, or one that could not be identified. */
        public ?string $resource,

        /** Who the check was about, and the scope it was asked in. */
        public DecisionProvenance $requested,

        /** Who the check was about, and the scope it was decided in. */
        public DecisionProvenance $decided,
    ) {}

    /**
     * Return the request as the explanation's JSON schema gives it.
     *
     * @return array<string, ReferenceArray|ScopeArray|string|null>
     */
    public function toArray(): array
    {
        return [
            'action'          => $this->action,
            'resource'        => $this->resource,
            'subject'         => GrantProvenance::referenceArray($this->decided->subject),
            'identity'        => GrantProvenance::referenceArray($this->decided->identity),
            'previewer'       => GrantProvenance::referenceArray($this->decided->previewer),
            'requested_scope' => self::scopeOf($this->requested),
            'decision_scope'  => self::scopeOf($this->decided),
        ];
    }

    /**
     * Return the scope of the provenance, its tenant and its application.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance  $provenance
     * @return ScopeArray
     */
    private static function scopeOf(DecisionProvenance $provenance): array
    {
        return ['tenant' => GrantProvenance::referenceArray($provenance->tenant), 'application' => $provenance->application];
    }
}
