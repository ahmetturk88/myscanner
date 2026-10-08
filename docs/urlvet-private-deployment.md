# Private URLVet integration rehearsal

The existing host URLVet deployment is left intact. This optional override starts
another backend/cache/browser under the isolated VPS rehearsal project. Backend
source is pinned to upstream commit 657a8dafeb9c9109a339087ea07cf922aaddc52a.
The build downloads public upstream code, copies only its binary and assets into
the runtime image, and never copies the host or upstream .env into that image.
The backend runs as UID 10001. Independent file secrets provide cache auth and
an internal JWT signing key. No provider API, cache or browser port is published.

Prepare existing secrets once more to add the two independent provider secrets:

```powershell
python scripts/init_vps_stack.py
python -m unittest discover -s tests -p test_urlvet_deployment.py -v
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml config --quiet
```

The browser and Valkey images are locked to the digests reported from the user's
existing deployment. This fixes reproducibility, not image security clearance;
actual merged configuration/build/startup must still be tested. URLVet's admin
UI is not deployed and no admin password is provided to this backend.

After image validation, build/start the override, check backend health from the
worker at http://urlvet:8080/health, then submit a new URL scan through MyScanner
and confirm the saved report survives worker/web restarts. All commands for this
stack must continue to include both Compose files once this override is enabled.
Reverting to the core configuration switches back to the existing host provider.

## Boundaries still requiring launch work

This is private connectivity, not proof of complete target egress isolation.
The backend and browser have public outgoing connectivity on a network with no
PostgreSQL or MyScanner Redis attachment. Private destination restrictions,
redirect/rebinding/browser request enforcement, CPU/load tests and screenshot
serving need verification before public use. Do not expose the provider admin
API or Chrome debugging ports. User data retention in reports/screenshots/cache
and upstream licensing obligations also remain launch gates. Never describe
unknown/partial evidence as confirmed safety.
