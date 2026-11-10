<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;

/**
 * A sibling package's service provider that binds its own subject resolver,
 * requirement checker, session policy source and authentication context in its
 * `register()`, as `laravel-iam` does, and declares a context key on the key
 * catalogue once it is built, while the authentication context bound is its
 * own.
 *
 * It binds each seam only while the seam is unbound or holds the authorization
 * package's own default, which it tells from any other binding by reading the
 * binding table: the package's default is a closure its service provider
 * declares. Any other binding is the application's, and is kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SiblingSeamsProvider extends ServiceProvider
{
    /** @var string The context key the provider declares. */
    public const string KEY = 'sibling.session_id';

    /**
     * Bind each seam the provider may bind over, and declare its key on the
     * catalogue once it is built.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $seams = [
            SubjectResolver::class                  => static fn (): SubjectResolver => new StubSubjectResolver,
            AuthenticationRequirementChecker::class => static fn (): AuthenticationRequirementChecker => new StubRequirementChecker(RequirementResult::met()),
            SessionPolicySource::class              => static fn (): SessionPolicySource => new StubSessionPolicySource([]),
            AuthenticationContext::class            => static fn (): AuthenticationContext => new ContributingAuthenticationContext(['sibling']),
        ];

        foreach ($seams as $contract => $concrete) {
            if (!self::isReplaceable($this->app, $contract)) {
                continue;
            }

            $this->app->bind($contract, $concrete);
        }

        $this->app->afterResolving(ContextKeyCatalogue::class, static function (ContextKeyCatalogue $catalogue, ContainerContract $container): void {
            if (!$container->make(AuthenticationContext::class) instanceof ContributingAuthenticationContext || $catalogue->find(self::KEY) !== null) {
                return;
            }

            $catalogue->declare(self::KEY, ContextKeyType::STRING);
        });
    }

    /**
     * Determine whether the seam is unbound, or bound to a closure the
     * authorization package's service provider declares.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  class-string  $contract
     * @return bool
     */
    private static function isReplaceable(ContainerContract $container, string $contract): bool
    {
        if (!$container->bound($contract)) {
            return true;
        }

        if (!$container instanceof Container) {
            return false;
        }

        $concrete = $container->getBindings()[$contract]['concrete'] ?? null;

        return $concrete instanceof \Closure && (new \ReflectionFunction($concrete))->getClosureScopeClass()?->getName() === AuthorizationServiceProvider::class;
    }
}
