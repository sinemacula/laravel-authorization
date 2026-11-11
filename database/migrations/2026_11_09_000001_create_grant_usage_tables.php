<?php

/**
 * Create the grant usage tables (N102): `grant_usage`, the last observed use of
 * each grant route, and `usage_coverage`, the periods grant usage tracking was
 * on.
 *
 * A usage row is keyed by the route's key (see `Usage\GrantUsageKey`), a stable
 * digest of its source kind, target, grantee, tenant, application and reach,
 * and keeps the columns that make the stored grant it starts from unique, so
 * the usage pruner can tell whether that grant still exists, the grant's
 * creation when it was observed, so a regrant never inherits the old grant's
 * use, and the start of the last bucket it was observed in, in UTC. A coverage
 * row is one period, `[covered_from, covered_until)` in UTC.
 *
 * Both honour the configured table names and the package's connection. The
 * reference columns compare their exact bytes on every database, as the grant
 * tables' do (`ExactReferences`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\ExactReferences;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionGuard;

return new class extends Migration {
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up(): void
    {
        $usage    = TableNames::get('grant_usage');
        $coverage = TableNames::get('usage_coverage');

        $schema = Schema::connection($this->getConnection());
        $guard  = new MigrationCollisionGuard($schema);

        $guard->ensureNotExists($usage);
        $guard->ensureNotExists($coverage);

        $exact = new ExactReferences($schema->getConnection());

        $schema->create($usage, static function (Blueprint $blueprint) use ($usage, $exact): void {
            // The route's key, a SHA-256 digest in hexadecimal.
            $blueprint->string('grant_key', 64)->primary();

            // The stored grant the route starts from, by the columns that make
            // it unique. References are bounded to 191 characters, as the suite
            // bounds them.
            $blueprint->string('grant_source', 16);
            $blueprint->string('grant_id', 191);
            $blueprint->string('authorizable_type', 191);
            $blueprint->string('authorizable_id', 191);
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();
            $blueprint->string('application', 191)->nullable();

            // The grant's creation when it was observed, and the start of the
            // last bucket the route was observed in, both in UTC.
            $blueprint->dateTime('grant_created_at')->nullable();
            $blueprint->dateTime('last_observed_at');

            $blueprint->index(['grant_source', 'grant_id'], $usage . '_grant_index');

            // On MySQL the reference columns compare their exact bytes, as on
            // the other databases.
            $exact->apply($blueprint);
        });

        $schema->create($coverage, static function (Blueprint $blueprint) use ($coverage): void {
            $blueprint->bigIncrements('id');

            // The period tracking was on, `[covered_from, covered_until)` in
            // UTC.
            $blueprint->dateTime('covered_from');
            $blueprint->dateTime('covered_until');

            $blueprint->index('covered_until', $coverage . '_until_index');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        $usage    = TableNames::get('grant_usage');
        $coverage = TableNames::get('usage_coverage');

        $schema = Schema::connection($this->getConnection());

        $schema->dropIfExists($coverage);
        $schema->dropIfExists($usage);
    }

    /**
     * The connection the tables live on, the one the package's models read and
     * write them on: `authorization.connection`, or the default when unset.
     *
     * @return string|null
     */
    #[Override]
    public function getConnection(): ?string
    {
        return AuthorizationConnection::name();
    }
};
