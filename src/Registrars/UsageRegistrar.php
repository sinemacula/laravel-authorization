<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobProcessed;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder;
use SineMacula\Laravel\Authorization\Usage\UsageTracking;

/**
 * Wires grant usage tracking (N94, N101, N102) into the application.
 *
 * `register()` binds the usage store and the recorder. The store, the package's
 * own on its tables by default, is a seam bound through `SeamBindings`: its
 * default is held under a package-owned key, a binding an application or a
 * sibling package made before the package registers stands, and one made after
 * replaces it. The recorder is one per worker for as long as the worker runs,
 * so its noting of each route once a bucket holds across the requests and jobs
 * it serves.
 *
 * `boot()`, only while tracking is on, has each recorder flush what it noted as
 * the container that resolved it terminates, at the end of each request and
 * command, and after each queued job, processed or failed. Each container is
 * watched from its first resolution of a recorder, on that container, as
 * `forgetResolutionsOnRebinding()` watches a rebinding, so an Octane sandbox,
 * which resolves a recorder of its own, flushes that one as it terminates, and
 * nothing is built on the application it was cloned from; a recorder no check
 * built is never built to flush. The containers are held weakly, so a sandbox
 * thrown away is forgotten, and the queue's events are listened for once,
 * flushing the recorder of each container still held. With tracking off it
 * registers nothing, so nothing listens and nothing runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class UsageRegistrar
{
    /** @var string The package-owned key the default usage store is held under. */
    public const string DEFAULT_STORE = 'authorization.default:' . GrantUsageStore::class;

    /**
     * Create a new registrar instance.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     */
    public function __construct(

        /** The application the tracking is wired into. */
        private Application $app,
    ) {}

    /**
     * Bind the usage store, as a seam an application may bind itself (see
     * `SeamBindings`), and the recorder.
     *
     * @param  \SineMacula\Laravel\Authorization\Registrars\SeamBindings  $seams
     * @return void
     */
    public function register(SeamBindings $seams): void
    {
        $seams->bindDefault(GrantUsageStore::class, DatabaseGrantUsageStore::class);

        $this->app->singleton(GrantUsageRecorder::class);
    }

    /**
     * Have each recorder flush what it noted at the end of each request,
     * command and queued job of the container that resolved it, while tracking
     * is on.
     *
     * @return void
     */
    public function boot(): void
    {
        if (!UsageTracking::isEnabled()) {
            return;
        }

        /** @var \WeakMap<\Illuminate\Contracts\Container\Container, \SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder> $recorders */
        $recorders = new \WeakMap;

        $this->app->afterResolving(GrantUsageRecorder::class, static function (GrantUsageRecorder $recorder, Container $container) use ($recorders): void {
            $isWatched             = isset($recorders[$container]);
            $recorders[$container] = $recorder;

            if ($isWatched || !$container instanceof Application) {
                return;
            }

            $container->terminating(static function () use ($container, $recorders): void {
                $recorders[$container]->flush();
            });
        });

        $this->app->make(Dispatcher::class)->listen([JobProcessed::class, JobExceptionOccurred::class], static function () use ($recorders): void {
            foreach ($recorders as $recorder) {
                $recorder->flush();
            }
        });
    }
}
