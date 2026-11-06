<?php

declare(strict_types = 1);

return [

    /*
    |---------------------------------------------------------------------------
    | Authorization Language Lines
    |---------------------------------------------------------------------------
    |
    | Messages the package can put in front of a client. They load under the
    | `authorization` namespace; publish them with the `authorization-lang` tag
    | to reword them or to add a locale.
    |
    */

    'denied' => 'This action is unauthorized.',

    'role_required' => 'This action requires a role you do not have.',

    'insufficient_authentication' => 'This action requires further authentication.',

    /*
    |---------------------------------------------------------------------------
    | Denial Reasons
    |---------------------------------------------------------------------------
    |
    | One line per reason code a decision can be denied with, keyed by the code.
    | A Laravel policy class deciding through the package's
    | `DecidesThroughAuthorization` trait denies with the line of the reason,
    | alongside the code itself.
    |
    */

    'explicit_deny' => 'This action is not allowed.',

    'no_match' => 'This action is unauthorized.',

    'condition_failed' => 'This action is not allowed in the current circumstances.',

    'invalid_policy' => 'This action cannot be authorized at the moment.',

    'subject_inactive' => 'This account is not active.',

    'subject_unresolved' => 'You must be signed in to perform this action.',

    'resource_unresolved' => 'The resource of this action could not be identified.',

    'tenant_scope' => 'This resource is outside your current scope.',

    'guardrail' => 'This action is restricted here.',

    'boundary' => 'This action is outside what you may be permitted to do.',

    'session_policy' => 'This action is outside what the current session may do.',

];
