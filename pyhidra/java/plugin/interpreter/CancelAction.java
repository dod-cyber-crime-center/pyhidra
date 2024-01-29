package dc3.pyhidra.plugin.interpreter;

import java.awt.event.KeyEvent;
import javax.swing.ImageIcon;

import dc3.pyhidra.plugin.PyhidraPlugin;
import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

import static docking.DockingUtils.CONTROL_KEY_MODIFIER_MASK;

final class CancelAction extends ToggleDockingAction {

	private final TaskMonitor monitor;

	CancelAction(TaskMonitor monitor) {
		super("Cancel", PyhidraPlugin.class.getSimpleName());
		this.monitor = monitor;
		setDescription("Interrupt the interpreter");
		ImageIcon image = ResourceManager.loadImage("images/dialog-cancel.png");
		setToolBarData(new ToolBarData(image));
		setEnabled(true);
		KeyBindingData key = new KeyBindingData(KeyEvent.VK_I, CONTROL_KEY_MODIFIER_MASK);
		setKeyBindingData(key);
		markHelpUnnecessary();
		if (monitor instanceof InterpreterTaskMonitor) {
			((InterpreterTaskMonitor) monitor).setCancelAction(this);
		}
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (isSelected()) {
			monitor.clearCancelled();
		} else {
			monitor.cancel();
		}
	}

	@Override
	public boolean isSelected() {
		return monitor.isCancelled();
	}
};
