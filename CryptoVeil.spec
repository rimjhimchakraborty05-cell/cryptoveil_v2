# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['desktop_app.py'],
    pathex=[],
    binaries=[],
    datas=[('dashboard', 'dashboard'), ('extension', 'extension'), ('process_rules.json', '.')],
    hiddenimports=['uvicorn', 'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto', 'uvicorn.loops.asyncio', 'uvicorn.protocols', 'uvicorn.protocols.http', 'uvicorn.protocols.http.auto', 'uvicorn.protocols.http.h11_impl', 'uvicorn.protocols.websockets', 'uvicorn.protocols.websockets.auto', 'uvicorn.protocols.websockets.wsproto_impl', 'uvicorn.protocols.websockets.websockets_impl', 'fastapi', 'starlette', 'webview', 'webview.platforms', 'webview.platforms.winforms', 'webview.platforms.edgechromium', 'agent', 'agent.server.main', 'agent.server.routes', 'agent.server.ws_manager', 'agent.sensors.browser_profiles', 'agent.bus.events', 'agent.bus.event_bus', 'agent.engines.mitre_engine', 'agent.engines.network_engine', 'agent.forensics.audit_logger', 'agent.forensics.merkle_tree', 'agent.forensics.off_host_store', 'agent.reports.scheduler', 'agent.reports.store', 'agent.sensors.clipboard_watcher', 'agent.sensors.entropy_watcher', 'agent.sensors.process_watcher'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='CryptoVeil',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='CryptoVeil',
)
