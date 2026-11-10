<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin;

/**
 * One seam as the configuration report shows it: where its binding came from,
 * the class it builds when that is known without building it, or the classes a
 * declared factory may build, or where the closure deciding it is written, how
 * long what it builds lives, the extenders registered on it, and what is known
 * of its history.
 *
 * `previously_resolved` says the contract was resolved before; it says nothing
 * of whether anything is held now. `extenders` are the extenders still
 * registered: one Laravel applied at once to an instance it already held leaves
 * no trace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SeamRow
{
    /**
     * Create a new row.
     *
     * @param  string  $contract
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin  $origin
     * @param  list<string>  $classes
     * @param  string|null  $factory
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime|null  $lifetime
     * @param  list<string>  $extenders
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding  $binding
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord|null  $record
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Declaration|null  $declaration
     */
    public function __construct(

        /** The contract. */
        public string $contract,

        /** Where its binding came from. */
        public Origin $origin,

        /** The class it builds, or the classes a declared factory may build, when known without building them. */
        public array $classes,

        /** Where the closure deciding what it builds is written, when no class is known, else null. */
        public ?string $factory,

        /** How long what it builds lives, or null when nothing is bound. */
        public ?Lifetime $lifetime,

        /** The extenders registered on it, in order: the configured grant hooks by their setting, any other by where it is written. */
        public array $extenders,

        /** What the container holds for it now. */
        public CurrentBinding $binding,

        /** What the package recorded as it bound it, or null when it binds none. */
        public ?SeamRecord $record,

        /** What a sibling package declared of it, or null when none did. */
        public ?Declaration $declaration,
    ) {}

    /**
     * Return the class it builds, or null when it is not one known class.
     *
     * @return string|null
     */
    public function class(): ?string
    {
        return \count($this->classes) === 1 && $this->declaration?->isFactory() !== true ? $this->classes[0] : null;
    }

    /**
     * Determine whether what it builds is decided by custom code only when it
     * is first resolved: no class is known, and a closure decides.
     *
     * @return bool
     */
    public function isDecidedAtFirstUse(): bool
    {
        return $this->classes === [] && $this->factory !== null;
    }

    /**
     * Return the row in the report's versioned shape.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $declaration = $this->declaration;

        return [
            'contract'            => $this->contract,
            'origin'              => $this->origin->value,
            'class'               => $this->class(),
            'classes'             => $this->classes,
            'decides'             => $declaration?->decides,
            'factory'             => $this->factory,
            'lifetime'            => $this->lifetime?->value,
            'extenders'           => $this->extenders,
            'config_key'          => $this->record?->configKey,
            'alias'               => $this->binding->alias,
            'deferred_provider'   => $this->binding->deferredProvider ?? $this->record?->deferredProvider,
            'previously_resolved' => $this->binding->previouslyResolved,
            'declaration'         => $declaration === null ? null : [
                'owner'    => $declaration->owner,
                'classes'  => $declaration->classes,
                'decides'  => $declaration->decides,
                'lifetime' => $declaration->lifetime->value,
                'state'    => $declaration->standing($this->binding->concrete),
            ],
        ];
    }
}
