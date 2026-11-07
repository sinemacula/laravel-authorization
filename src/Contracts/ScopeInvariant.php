<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Marks a context source, an authentication context, a request or environment
 * context, a subject attribute provider or an authentication requirement
 * checker whose values depend only on the request (the caller, the session, the
 * request itself and the clock), never on the record a check is about, so
 * `whereAuthorized()` may read it once for a query rather than once per row
 * (AUTHZ-10.1).
 *
 * The scope compiles a statement that reads a namespace, or states an
 * authentication requirement, only when every seam supplying it is marked; any
 * other is refused as `scope_variant_source`. The package's defaults are
 * marked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ScopeInvariant {}
