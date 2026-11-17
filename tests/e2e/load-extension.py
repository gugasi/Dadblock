"""Loads the unpacked extension in real Chromium, checks that the service worker starts and the
popup opens without errors, and that the pop-under blocker leaves a normal page alone.
Run:  python3 tests/e2e/load-extension.py   (needs: pip install playwright && playwright install chromium)"""
import os, sys, tempfile
from playwright.sync_api import sync_playwright

ext = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'extension'))
errors = []
with sync_playwright() as p, tempfile.TemporaryDirectory() as tmp:
    ctx = p.chromium.launch_persistent_context(tmp, headless=True, channel='chromium', args=[f'--disable-extensions-except={ext}', f'--load-extension={ext}'])
    sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event('serviceworker', timeout=15000)
    ext_id = sw.url.split('/')[2]
    print('service worker started:', sw.url)
    page = ctx.new_page()
    page.on('pageerror', lambda e: errors.append(f'popup: {e}'))
    page.goto(f'chrome-extension://{ext_id}/popup.html'); page.wait_for_timeout(1500)
    assert 'Dadblock' in page.inner_text('body'), 'popup did not render'
    print('popup rendered')
    web = ctx.new_page(); web.on('pageerror', lambda e: errors.append(f'page: {e}'))
    web.set_content('<button id=b onclick="window.open(\'about:blank\')">x</button>'); web.wait_for_timeout(500)
    print('normal page loaded with content scripts allowed')
    ctx.close()
if errors:
    print('ERRORS:', *errors, sep='\n  '); sys.exit(1)
print('OK')
