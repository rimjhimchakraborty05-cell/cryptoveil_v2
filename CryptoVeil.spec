# Build on Windows. Runtime evidence and private keys are deliberately excluded.
from PyInstaller.utils.hooks import collect_submodules

analysis = Analysis(
    ['desktop_app.py'], pathex=[], binaries=[],
    datas=[('dashboard', 'dashboard'), ('extension', 'extension'),
           ('process_rules.json', '.'), ('cryptoveil.ico', '.')],
    hiddenimports=collect_submodules('agent') + ['uvicorn.loops.asyncio',
        'uvicorn.protocols.http.h11_impl', 'webview.platforms.winforms', 'webview.platforms.edgechromium'],
    hookspath=[], runtime_hooks=[], excludes=[], noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(pyz, analysis.scripts, [], exclude_binaries=True, name='CryptoVeil',
          console=False, icon='cryptoveil.ico', debug=False, strip=False, upx=False)
coll = COLLECT(exe, analysis.binaries, analysis.datas, strip=False, upx=False, name='CryptoVeil')
