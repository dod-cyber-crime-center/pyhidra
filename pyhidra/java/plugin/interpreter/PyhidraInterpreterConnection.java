package dc3.pyhidra.plugin.interpreter;

import java.util.Arrays;
import java.util.List;

import dc3.pyhidra.plugin.PyhidraPlugin;
import docking.action.DockingAction;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;

/**
 * InterpreterConnection to be implemented by a Python object
 *
 * The Python object implementing this interface contains numerous references to Java objects.
 * To prevent recursive reference counting, <b>do not</b> directly store any instance of this
 * interface a Java object.
 */
public interface PyhidraInterpreterConnection extends InterpreterConnection {

	/**
	 * Close the underlying Python interpreter thread
	 */
	public void close();

	/**
	 * Restart the interpreter
	 */
	public void restart();

	/**
	 * Gets the interpreter console
	 * @return the interpreter console
	 */
	public InterpreterConsole getConsole();

	/**
	 * Gets the PyhidraPlugin for the interpreter
	 * @return the PyhidraPlugin
	 */
	public PyhidraPlugin getPlugin();

	/**
	 * Sets the DockingActions used by the interpreter
	 *
	 * This is intended to provide the actions to the Python object so they may
	 * be properly disposed when the plugin is cleaning up.
	 * @param actions the interpreter's docking actions
	 */
	public void setActions(List<DockingAction> actions);

	/**
	 * Static helper method for completing initialization of the interpreter
	 *
	 * This initialized all the docking actions for the interpreter and puts all
	 * the necessary callbacks in place.
	 * @param self the interpreter connection
	 */
	public static void initialize(PyhidraInterpreterConnection self) {
		// this roundabout design is to avoid recursive reference counting
		PyhidraPlugin plugin = self.getPlugin();
		InterpreterConsole console = self.getConsole();
		console.addFirstActivationCallback(self::restart);
		DockingAction[] actions = new DockingAction[]{
			new CancelAction(plugin.script.getMonitor()),
			new RestartAction(self)
		};
		for (DockingAction action : actions) {
			console.addAction(action);
		}
		self.setActions(Arrays.asList(actions));
		plugin.script.setCloser(self::restart);
	}
}
