package dc3.pyhidra.plugin.interpreter;

import ghidra.util.task.TaskMonitorAdapter;

public final class InterpreterTaskMonitor extends TaskMonitorAdapter {

	CancelAction cancelAction;

	InterpreterTaskMonitor() {
		setCancelEnabled(true);
	}

	void setCancelAction(CancelAction cancelAction) {
		this.cancelAction = cancelAction;
	}

	@Override
	public void cancel() {
		super.cancel();
		if (cancelAction != null) {
			cancelAction.setSelected(true);
		}
	}

	@Override
	public void clearCanceled() {
		super.clearCanceled();
		if (cancelAction != null) {
			cancelAction.setSelected(false);
		}
	}
}
