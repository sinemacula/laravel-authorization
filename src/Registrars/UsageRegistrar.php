<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

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
 * `register()` binds the usage store, the package's own on its tables by
 * default, held under a package-owned key so an application binding the
 * contract itself keeps its binding, and the recorder, one per worker for as
 * long as the worker runs, so its noting of each route once a bucket holds
 * across the requests and jobs it serves.
 *
 * `boot()`, only while tracking is on, has the recorder flush what it noted as
 * the application terminates, at the end of each request and command, and after
 * each queued job, processed or failed; with tracking off it registers nothing,
 * so nothing listens and nothing runs.
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
     * Bind the usage store and the recorder.
     *
     * @return void
     */
    public function register(): void
    {
        $this->app->scoped(self::DEFAULT_STORE, DatabaseGrantUsageStore::class);
        $this->app->bind(GrantUsageStore::class, static fn (Application $app): mixed => $app->make(self::DEFAULT_STORE));
        $this->app->singleton(GrantUsageRecorder::class);
    }

    /**
     * Have the recorder flush what it noted at the end of each request, command
     * and queued job, while tracking is on.
     *
     * @return void
     */
    public function boot(): void
    {
        if (!UsageTracking::isEnabled()) {
            return;
        }

        $app   = $this->app;
        $flush = static function () use ($app): void {
            if (!$app->resolved(GrantUsageRecorder::class)) {
                return;
            }

            $app->make(GrantUsageRecorder::class)->flush();
        };

        $app->terminating($flush);

        $app->make(Dispatcher::class)->listen([JobProcessed::class, JobExceptionOccurred::class], $flush);
    }
}
