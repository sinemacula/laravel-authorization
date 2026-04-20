<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\ObservedBy;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException;
use SineMacula\Laravel\Authorization\Observers\PolicyObserver;
use SineMacula\Laravel\Authorization\Traits\HasSystemProtection;

/**
 * Eloquent model for policy rows.
 *
 * The `document` column persists the full statement body as JSON.
 * Reads round-trip the column through the evaluation policy's
 * `fromArray()` factory; a failing round-trip raises an invalid
 * policy document exception rather than leaving the consumer with a
 * partial object. The `is_system` flag marks platform-shipped
 * policies as delete-protected: deletion or a rename of an
 * `is_system = true` row raises `SystemPolicyProtectedException`
 * unless `forceSystem()` is invoked to unlock the next operation on
 * the instance.
 *
 * @property string $id
 * @property string $name
 * @property string|null $description
 * @property array<string, mixed> $document
 * @property bool $is_system
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Fillable('name', 'description', 'document', 'is_system')]
#[ObservedBy(PolicyObserver::class)]
class Policy extends Model
{
    use HasSystemProtection, HasUuids;

    /** @var string Placeholder used when exception context lacks a policy name. */
    private const string UNNAMED_PLACEHOLDER = '[unnamed]';

    /** @var array<string, string> Attribute cast map. */
    protected $casts = [
        'document'  => 'array',
        'is_system' => 'boolean',
    ];

    /**
     * Create a new Eloquent model instance.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        /** @var string $table */
        $table       = config('authorization.tables.policies', 'policies');
        $this->table = $table;
    }

    /**
     * Set the document attribute, validating it round-trips through
     * the evaluation policy factory.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public function setDocumentAttribute(mixed $value): void
    {
        $document = $this->normaliseDocument($value);
        $document = $this->withName($document);

        try {
            EvaluationPolicy::fromArray($document);
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidPolicyDocumentException(policyName: $this->resolveName(), reason: $exception->getMessage(), previous: $exception);
        }

        $encoded = \json_encode($document);

        // @codeCoverageIgnoreStart
        // Defensive: the preceding `EvaluationPolicy::fromArray` round-trip
        // would itself have failed on a non-JSON-encodable payload (it calls
        // `json_encode` during trace normalisation), so reaching this branch
        // requires a resource type or a circular reference smuggled past the
        // factory validator.
        if ($encoded === false) {
            throw new InvalidPolicyDocumentException(policyName: $this->resolveName(), reason: 'policy document is not JSON-encodable.');
        }
        // @codeCoverageIgnoreEnd

        $this->attributes['document'] = $encoded;
    }

    /**
     * Hydrate the policy into an evaluation-ready value object.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public function toEvaluationPolicy(): EvaluationPolicy
    {
        $document = $this->normaliseDocument($this->document);
        $document = $this->withName($document);

        try {
            return EvaluationPolicy::fromArray($document);
        } catch (\Throwable $exception) {
            throw new InvalidPolicyDocumentException(policyName: $this->name, reason: $exception->getMessage(), previous: $exception);
        }
    }

    /**
     * Return the attribute names whose dirty state triggers the
     * system-protection guard on `updating`. For policies, both
     * `name` and `document` changes are protected — the document
     * carries the authorization payload and its mutation is the
     * security-relevant edit on the Policy table.
     *
     * @return list<string>
     */
    protected function systemProtectedFields(): array
    {
        return ['name', 'document'];
    }

    /**
     * Construct the per-model exception raised when a protected
     * mutation on a system policy is refused.
     *
     * @param  string  $operation
     * @return \Throwable
     */
    protected function systemProtectionException(string $operation): \Throwable
    {
        // Use the ORIGINAL name — on a rename, `getAttribute('name')`
        // already reflects the mutated value. Audit consumers want
        // "which policy was targeted" (the canonical persisted
        // name), not "what the attempted rename would produce."
        /** @var string $policyName */
        $policyName = $this->getOriginal('name', $this->getAttribute('name'));

        return new SystemPolicyProtectedException(policyName: $policyName, operation: $operation);
    }

    /**
     * Coerce a raw document value into an associative array.
     *
     * @param  mixed  $value
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private function normaliseDocument(mixed $value): array
    {
        if (\is_array($value)) {
            /** @var array<string, mixed> $value */
            return $value;
        }

        if (\is_string($value) && $value !== '') {
            $decoded = \json_decode($value, true);

            if (\is_array($decoded)) {
                /** @var array<string, mixed> $decoded */
                return $decoded;
            }
        }

        throw new InvalidPolicyDocumentException(policyName: $this->resolveName(), reason: 'policy document must be a JSON object or array.');
    }

    /**
     * Resolve the policy name used in exception context.
     *
     * @return string
     */
    private function resolveName(): string
    {
        $name = $this->name ?? ($this->attributes['name'] ?? null);

        return \is_string($name) && $name !== '' ? $name : self::UNNAMED_PLACEHOLDER;
    }

    /**
     * Ensure the document body carries the model's name.
     *
     * @param  array<string, mixed>  $document
     * @return array<string, mixed>
     */
    private function withName(array $document): array
    {
        if (!isset($document['name']) || !\is_string($document['name']) || $document['name'] === '') {
            $name = $this->name ?? ($this->attributes['name'] ?? null);

            if (\is_string($name) && $name !== '') {
                $document['name'] = $name;
            }
        }

        return $document;
    }
}
