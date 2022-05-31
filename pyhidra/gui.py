import os
import sys


def gui():
    """
    Starts the Ghidra GUI
    """
    if not "GHIDRA_INSTALL_DIR" in os.environ:
        import tkinter.messagebox
        msg = "GHIDRA_INSTALL_DIR not set.\nPlease see the README for setup instructions"
        tkinter.messagebox.showerror("Improper Setup", msg)
        sys.exit()
    import pyhidra
    pyhidra.GuiPyhidraLauncher().start()


def get_current_interpreter():
    """
    Gets the underlying GhidraScript for the focused Pyhidra InteractiveConsole.
    This will always return None unless it is being access from a function
    called from within the interactive console.

    :return: The GhidraScript for the active interactive console.
    """
    
    try:
        from ghidra.framework.main import AppInfo
        project = AppInfo.getActiveProject()
        if project is None:
            return None
        ts = project.getToolServices()
        tool = None
        for t in ts.getRunningTools():
            if t.getActiveWindow().isFocused():
                tool = t
                break
        if tool is None:
            return None
        for plugin in tool.getManagedPlugins():
            if plugin.name == 'PyhidraPlugin':
                return plugin.script
    except ImportError:
        return None
