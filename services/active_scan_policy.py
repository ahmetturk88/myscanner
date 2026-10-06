"""Keep intrusive scanners closed until verified target scope is implemented."""
ACTIVE_SCAN_NOTICE = 'Active scanning is temporarily unavailable. Verified target authorization is required before this service can be enabled.'

class TargetAuthorizationRequired(PermissionError):
    pass

def require_verified_target():
    # Intentionally no admin, client flag or environment-variable bypass.
    # A later change must validate a server-side grant and its exact scope.
    raise TargetAuthorizationRequired(ACTIVE_SCAN_NOTICE)

def skipped_active_analysis():
    return {'status': 'not_performed', 'reason': 'target_authorization_required',
            'tested_endpoints': [], 'details': [ACTIVE_SCAN_NOTICE]}
