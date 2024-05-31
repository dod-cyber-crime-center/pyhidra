import struct
import sys
import sysconfig
from pathlib import Path
from pyhidra import DeferredPyhidraLauncher


# creating a shortcut with the winapi to have a set app id is trivial right?




def create_shortcut(install_dir: Path = None):
    """Creates a shortcut to Ghidra (with pyhidra) on the desktop."""

    link = Path("~/Desktop/Ghidra (pyhidra).lnk").expanduser()
    if link.exists():
        sys.exit(f"{link} already exists")

    import ctypes
    import ctypes.wintypes

    class _GUID(ctypes.wintypes.DWORD * 4):
        def __init__(self, guid: str) -> None:
            ctypes.oledll.ole32.CLSIDFromString(guid, ctypes.byref(self))

    class _PROPERTYKEY(ctypes.wintypes.DWORD * 5):
        def __init__(self, key: str, pid: int) -> None:
            ctypes.oledll.ole32.IIDFromString(key, ctypes.byref(self))
            self[-1] = pid

    launcher = DeferredPyhidraLauncher(install_dir=install_dir)

    _PropertyVariant = struct.Struct(f"B7xP{ctypes.sizeof(ctypes.c_void_p())}x")
    _AppUserModelId = _PROPERTYKEY("{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}", 5)
    _CLSID_ShellLink = _GUID("{00021401-0000-0000-C000-000000000046}")
    _IID_IShellLinkW = _GUID("{000214F9-0000-0000-C000-000000000046}")
    _IID_IPersistFile = _GUID("{0000010B-0000-0000-C000-000000000046}")
    _IID_IPropertyStore = _GUID("{886d8eeb-8cf2-4446-8d02-cdba1dbdcf99}")

    _CLSCTX_INPROC_SERVER = 1
    _COINIT_APARTMENTTHREADED = 2
    _COINIT_DISABLE_OLE1DDE = 4
    _VT_LPWSTR = 31
    _APP_ID = launcher.app_info.name

    WINFUNCTYPE = ctypes.WINFUNCTYPE
    _CoCreateInstance = ctypes.oledll.ole32.CoCreateInstance
    _QueryInterface = WINFUNCTYPE(ctypes.HRESULT, _GUID, ctypes.c_void_p)(0, "QueryInterface")
    _Release = WINFUNCTYPE(ctypes.HRESULT)(2, "Release")
    _Save = WINFUNCTYPE(ctypes.HRESULT, ctypes.c_wchar_p, ctypes.wintypes.BOOL)(6, "Save")
    _SetPath = WINFUNCTYPE(ctypes.HRESULT, ctypes.c_wchar_p)(20, "SetPath")
    _SetDescription = WINFUNCTYPE(ctypes.HRESULT, ctypes.c_wchar_p)(7, "SetDescription")
    _SetIconLocation = WINFUNCTYPE(ctypes.HRESULT, ctypes.c_wchar_p, ctypes.c_int)(17, "SetIconLocation")
    _SetValue = WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, ctypes.c_void_p)(6, "SetValue")

    link = str(link)
    target = Path(sysconfig.get_path("scripts")) / "pyhidraw.exe"
    icon = str(launcher.install_dir / "support" / "ghidra.ico")
    p_link = ctypes.c_void_p()
    p_file = ctypes.c_void_p()
    p_store = ctypes.c_void_p()
    p_app_id = ctypes.wintypes.LPCWSTR(_APP_ID)
    ctypes.oledll.ole32.CoInitializeEx(None, _COINIT_APARTMENTTHREADED | _COINIT_DISABLE_OLE1DDE)
    try:
        ref = ctypes.byref(p_link)
        _CoCreateInstance(_CLSID_ShellLink, None, _CLSCTX_INPROC_SERVER, _IID_IShellLinkW, ref)
        _SetPath(p_link, ctypes.c_wchar_p(str(target)))
        _SetDescription(p_link, p_app_id)
        _SetIconLocation(p_link, ctypes.c_wchar_p(icon), 0)
        _QueryInterface(p_link, _IID_IPropertyStore, ctypes.byref(p_store))
        value = _PropertyVariant.pack(_VT_LPWSTR, ctypes.cast(p_app_id, ctypes.c_void_p).value)
        value = (ctypes.c_byte * len(value))(*value)
        _SetValue(p_store, ctypes.byref(_AppUserModelId), ctypes.byref(value))
        _QueryInterface(p_link, _IID_IPersistFile, ctypes.byref(p_file))
        _Save(p_file, ctypes.c_wchar_p(link), True)
    finally:
        if p_file:
            _Release(p_file)
        if p_link:
            _Release(p_link)
        if p_store:
            _Release(p_store)
        ctypes.oledll.ole32.CoUninitialize()

    print(f"Installed {link}")


def remove_shortcut():
    link = Path("~/Desktop/Ghidra (pyhidra).lnk").expanduser()
    if link.exists():
        link.unlink()
        print(f"Removed {link}")
