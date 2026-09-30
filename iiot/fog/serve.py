import argparse


def main(argv=None):
    ap = argparse.ArgumentParser(prog="iiot.fog.serve")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--psk", required=True)
    ap.add_argument("--admin-key", required=True)
    ap.add_argument("--no-tls", action="store_true")
    ap.add_argument("--cert-dir", default=".certs")
    ap.add_argument("--registry-path", default=None)
    a = ap.parse_args(argv)

    import uvicorn
    from iiot.common.state import FogConfig
    from iiot.fog.app import create_app

    app = create_app(FogConfig(psk=a.psk.encode(), admin_key=a.admin_key, registry_path=a.registry_path))
    kw = {}
    if not a.no_tls:
        from iiot.common.tls import ensure_self_signed_cert
        kw["ssl_certfile"], kw["ssl_keyfile"] = ensure_self_signed_cert(a.cert_dir)
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning", **kw)


if __name__ == "__main__":
    main()
