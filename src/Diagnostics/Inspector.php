<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Foundation\Application;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\EnvironmentContext;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\RequestContext;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingsReader;

/**
 * Build the configuration report from the container, the live configuration and
 * what the package recorded as it registered, without building any seam (N113).
 *
 * When the application booted for diagnosis (see `DiagnosticMode`), the report
 * holds what that boot found, every issue and the outcome of each check it ran
 * by building what a setting names, rather than checking again (see
 * `PackageState`). Otherwise the configuration is checked as the boot checks
 * it, collecting every issue, by its structural checks alone (see
 * `StructuralCheck`): on an application that booted, the boot's checks passed,
 * so issues show what changed since, or what a test set. Each seam is read from
 * the binding table, the instances held, the extenders, the aliases and the
 * deferred services, and compared by identity with the package's record and the
 * siblings' declarations (see `SeamClassifier`); nothing is resolved, rebound,
 * refreshed or extended, and whether each seam was resolved is the same after
 * inspecting as before.
 *
 * Each part of the report is read on its own: a part that cannot be read is
 * left empty and makes the report incomplete, naming the part, and the rest is
 * still reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Inspector
{
    /** @var list<class-string> The seams the package binds or reads, in the order the report lists them; any other the package recorded or a sibling declared follows. */
    public const array SEAMS = [
        SubjectResolver::class,
        TenantTree::class,
        IdentityDirectory::class,
        ResourceTenantResolver::class,
        AuthenticationRequirementChecker::class,
        SessionPolicySource::class,
        PolicyStore::class,
        PolicyResolver::class,
        ActionCatalogue::class,
        ContextKeyCatalogue::class,
        AuthenticationContext::class,
        RequestContext::class,
        EnvironmentContext::class,
        GrantHook::class,
        GrantUsageStore::class,
        ConsoleSubjectResolver::class,
        ScopeRegistry::class,
    ];

    /**
     * Create a new inspector.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the package is registered in. */
        private Container $container,

        /** The application's configuration. */
        private Repository $config,
    ) {}

    /**
     * Return the report.
     *
     * @return \SineMacula\Laravel\Authorization\Diagnostics\ConfigurationReport
     */
    public function inspect(): ConfigurationReport
    {
        [$stored, $bootChecks] = $this->stored();

        $parts    = new ReportParts;
        $root     = $parts->read('configuration', fn (): mixed => $this->config->get('authorization', []), []);
        $findings = $parts->read('issues', fn (): ConfigFindings => $stored ?? ConfigValidator::issues($root, $this->container), new ConfigFindings([], []));
        $seams    = $parts->read('seams', $this->seams(...), []);

        return new ConfigurationReport(
            settings: $parts->read('settings', static fn (): array => (new SettingsReader($root, $findings, $bootChecks))->rows(), []),
            seams: $seams,
            grantHooks: $parts->read(
                'grant_hooks',
                fn (): array => GrantHookOrder::of(\is_array($root) ? $root['grant_hooks'] ?? [] : [], $this->classifier()->classify(GrantHook::class)),
                [],
            ),
            connection: $parts->read('connection', fn (): array => (new ConnectionReader($this->config))->read(), ConnectionReader::UNREAD),
            integrations: $parts->read('integrations', fn (): array => (new IntegrationReader($this->container, $this->config))->read(), []),
            issues: [...$findings->issues, ...$parts->failures()],
        );
    }

    /**
     * Return what the boot found and the outcome of each check it ran by
     * building what a setting names, when the application booted for diagnosis,
     * else nothing.
     *
     * @return array{\SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings|null, list<\SineMacula\Laravel\Authorization\Diagnostics\BootCheck>}
     */
    private function stored(): array
    {
        $state    = PackageState::of($this->container);
        $findings = $state?->isDiagnostic() === true ? $state->findings() : null;

        return $findings === null ? [null, []] : [$findings, $state->bootChecks()];
    }

    /**
     * Return every seam, as shown: those the package binds or reads, then any
     * other it recorded or a sibling declared.
     *
     * @return list<\SineMacula\Laravel\Authorization\Diagnostics\SeamRow>
     */
    private function seams(): array
    {
        $classifier = $this->classifier();
        $contracts  = \array_values(\array_unique([...self::SEAMS, ...\array_keys($this->registry()->all()), ...\array_keys($this->declarations()->all())]));

        return \array_map($classifier->classify(...), $contracts);
    }

    /**
     * Return the classifier of the seams.
     *
     * @return \SineMacula\Laravel\Authorization\Diagnostics\SeamClassifier
     */
    private function classifier(): SeamClassifier
    {
        $basePath = $this->container instanceof Application ? $this->container->basePath() : null;

        return new SeamClassifier($this->container, $this->registry(), $this->declarations(), $basePath);
    }

    /**
     * Return what the package recorded as it registered, or an empty record
     * when it registered none in this container.
     *
     * @return \SineMacula\Laravel\Authorization\Diagnostics\BindingRegistry
     */
    private function registry(): BindingRegistry
    {
        $registry = ContainerState::instance($this->container, BindingRegistry::class);

        return $registry instanceof BindingRegistry ? $registry : new BindingRegistry;
    }

    /**
     * Return what sibling packages declared, or none when none did.
     *
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Declarations
     */
    private function declarations(): Declarations
    {
        $declarations = ContainerState::instance($this->container, Declarations::class);

        return $declarations instanceof Declarations ? $declarations : new Declarations;
    }
}
