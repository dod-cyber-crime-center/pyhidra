package dc3.pyhidra.plugin.interpreter;

import java.awt.event.KeyEvent;
import javax.swing.ImageIcon;

import dc3.pyhidra.plugin.PyhidraPlugin;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import resources.ResourceManager;

import static docking.DockingUtils.CONTROL_KEY_MODIFIER_MASK;

class RestartAction extends DockingAction {

	private final Runnable restarter;

	RestartAction(PyhidraInterpreterConnection connection) {
		super("Restart", PyhidraPlugin.class.getSimpleName());
		restarter = connection::restart;
		setDescription("Restart the interpreter");
		ImageIcon image = ResourceManager.loadImage("images/reload3.png");
		setToolBarData(new ToolBarData(image));
		setEnabled(true);
		KeyBindingData key = new KeyBindingData(KeyEvent.VK_D, CONTROL_KEY_MODIFIER_MASK);
		setKeyBindingData(key);
		markHelpUnnecessary();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		restarter.run();
	}

}
