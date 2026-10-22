"""Which builds of the Android app the server still supports, for in-app update prompts.

Builds are Play versionCodes. MOBILE_LATEST_BUILD is the newest build live on
Google Play: older apps show a "new version" card that can be dismissed.
MOBILE_MIN_BUILD is the oldest build still allowed: older apps show a full
update screen and cannot be used until they update. Both default to 0, which
turns the prompts off. Raise them only once the build is live on Play, or
people are sent to a store page that does not have it yet
(scripts/app_release.py sets them).
"""
import os

STORE_URL = 'https://play.google.com/store/apps/details?id=com.myscanners.app'


def _build(name):
    try:
        return max(0, int(os.environ.get(name, '') or 0))
    except ValueError:
        return 0


def policy(build):
    """What an app at `build` should do: 'required', 'available' or 'none'."""
    minimum = _build('MOBILE_MIN_BUILD')
    latest = max(_build('MOBILE_LATEST_BUILD'), minimum)
    update = 'none'
    if build is not None:
        update = 'required' if build < minimum else 'available' if build < latest else 'none'
    return {'update': update, 'latest_build': latest, 'min_build': minimum, 'store_url': STORE_URL}
