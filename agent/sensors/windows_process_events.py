"""Windows WMI process-start notifications, received outside the asyncio loop."""

import concurrent.futures
import threading


def is_wmi_timeout(error):
    values = [getattr(error, "hresult", 0)]
    details = getattr(error, "excepinfo", None)
    if details and len(details) > 5:
        values.append(details[5])
    return any(isinstance(code, int) and code & 0xFFFFFFFF == 0x80043001 for code in values)


class WindowsProcessEvents:
    def __init__(self, on_start):
        self.on_start = on_start
        self.status = "starting"
        self.last_error = None
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="cryptoveil-process-events", daemon=True
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=3)

    def _run(self):
        initialized = False
        try:
            import pythoncom
            import pywintypes
            import win32com.client

            pythoncom.CoInitialize()
            initialized = True
            service = win32com.client.GetObject(
                "winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2"
            )
            source = service.ExecNotificationQuery("SELECT * FROM Win32_ProcessStartTrace")
            self.status = "active"
            while not self._stop.is_set():
                try:
                    event = source.NextEvent(500)
                except pywintypes.com_error as exc:
                    if is_wmi_timeout(exc):
                        continue
                    raise
                trace = {
                    "pid": int(event.ProcessID),
                    "ppid": int(event.ParentProcessID),
                    "name": str(event.ProcessName),
                    "create_time": int(event.TIME_CREATED) / 10_000_000 - 11_644_473_600,
                }
                future = self.on_start(trace)
                while not self._stop.is_set():
                    try:
                        future.result(timeout=1)
                        break
                    except concurrent.futures.TimeoutError:
                        if future.done():
                            raise
                        continue
                if self._stop.is_set():
                    future.cancel()
        except Exception as exc:
            self.status = "unavailable"
            self.last_error = f"Windows process events unavailable: {exc}"
        finally:
            if initialized:
                pythoncom.CoUninitialize()
            if self._stop.is_set():
                self.status = "stopped"
