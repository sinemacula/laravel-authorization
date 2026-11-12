<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Where a grant that allowed a check came from, as an explanation records it
 * (AUTHZ-11.5): the permission or policy that applied, how it reached the
 * subject, the grantee it was granted to, the principal or its identity, the
 * roles it came through, the role held first and then each ancestor up to the
 * role that carries it, the tenant and application of the grant, where the
 * grant was made, and, for a role held through a break-glass activation, the
 * activation's key, never its note.
 *
 * It is read when the explained check resolves its grants, from the rows that
 * resolution reads, and never afterwards. A source that cannot say how a grant
 * reached the subject, a custom resolver or a policy store, is recorded as
 * `unavailable`, never guessed; a policy attached to the resource names the
 * resource, and the scope of its attachment is not recorded.
 *
 * It holds references and names alone, never a model or a value.
 *
 * @phpstan-type ReferenceArray array{type: string, id: string}
 * @phpstan-type ScopeArray array{tenant: array{type: string, id: string}|null, application: string|null}
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GrantProvenance
{
    /**
     * Create a new grant provenance.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource  $source
     * @param  string  $grant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantee
     * @param  bool  $isIdentity
     * @param  list<string>  $roles
     * @param  bool  $hasScope
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @param  string|null  $activation
     */
    public function __construct(

        /** How the grant reached the subject. */
        public GrantSource $source,

        /** The permission, as it was granted, or the policy, as a statement reference names it. */
        public string $grant,

        /** The principal or identity the grant was made to; null for a policy attached to the resource, or a source that cannot say. */
        public ?Reference $grantee = null,

        /** Whether the grantee is the subject's identity rather than its principal. */
        public bool $isIdentity = false,

        /** The name of each role the grant came through: the role held, then each ancestor up to the role that carries the grant. */
        public array $roles = [],

        /** Whether the tenant and application the grant was made in are known. */
        public bool $hasScope = false,

        /** The tenant the grant was made in; null for a platform-wide grant. */
        public ?Reference $tenant = null,

        /** The application the grant was made for; null for every application. */
        public ?string $application = null,

        /** The key of the break-glass activation the role was held through; null for any other route. */
        public ?string $activation = null,
    ) {}

    /**
     * Return the provenance of a grant whose source cannot say how it reached
     * the subject.
     *
     * @param  string  $grant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantee
     * @param  bool  $isIdentity
     * @return self
     */
    public static function unavailable(string $grant, ?Reference $grantee = null, bool $isIdentity = false): self
    {
        return new self(GrantSource::UNAVAILABLE, $grant, $grantee, $isIdentity);
    }

    /**
     * Return the provenance with the grant named as given, as a policy read by
     * its key is named once its name is known.
     *
     * @param  string  $grant
     * @return self
     */
    public function named(string $grant): self
    {
        return new self($this->source, $grant, $this->grantee, $this->isIdentity, $this->roles, $this->hasScope, $this->tenant, $this->application, $this->activation);
    }

    /**
     * Return the provenance as the explanation's JSON schema gives it: the
     * scope `unavailable` when it is not known, and the key of the break-glass
     * activation under `activation` for a route through one alone.
     *
     * @return array{source: string, grant: string, grantee: ReferenceArray|null, identity: bool, roles: list<string>, scope: ScopeArray|string, activation?: string}
     */
    public function toArray(): array
    {
        $route = [
            'source'   => $this->source->value,
            'grant'    => $this->grant,
            'grantee'  => self::referenceArray($this->grantee),
            'identity' => $this->isIdentity,
            'roles'    => $this->roles,
            'scope'    => $this->hasScope ? ['tenant' => self::referenceArray($this->tenant), 'application' => $this->application] : 'unavailable',
        ];

        return $this->activation === null ? $route : [...$route, 'activation' => $this->activation];
    }

    /**
     * Return the reference as its type and id, or null for none.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $reference
     * @return ReferenceArray|null
     */
    public static function referenceArray(?Reference $reference): ?array
    {
        return $reference === null ? null : ['type' => $reference->type, 'id' => $reference->id];
    }
}
