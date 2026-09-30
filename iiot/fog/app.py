import secrets

from fastapi import FastAPI

from iiot.common.state import FogConfig, FogState, new_state
from iiot.fog import onboarding


def create_app(config: FogConfig | None = None, state: FogState | None = None) -> FastAPI:
    if state is None:
        if config is None:
            config = FogConfig(psk=secrets.token_bytes(32), admin_key=secrets.token_urlsafe(24))
        state = new_state(config)
    app = FastAPI(title="IIoT Fog Node")
    app.state.fog = state
    app.include_router(onboarding.router)
    try:
        from iiot.fog.access import router as access_router
        app.include_router(access_router)
    except ImportError:
        pass
    return app
