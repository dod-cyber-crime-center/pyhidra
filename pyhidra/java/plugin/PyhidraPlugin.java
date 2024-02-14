package dc3.pyhidra.plugin;

import java.util.function.Consumer;

import dc3.pyhidra.plugin.interpreter.InterpreterGhidraScript;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "pyhidra plugin",
	description = "Native Python access in Ghidra. This plugin has no effect if Ghidra was not started via pyhidraw.",
	servicesRequired = { InterpreterPanelService.class }
)
public final class PyhidraPlugin extends ProgramPlugin {

	// set via reflection
	private static Consumer<PyhidraPlugin> initializer = (a) -> {
	};
	private Runnable finalizer = () -> {
	};

	public final InterpreterGhidraScript script = new InterpreterGhidraScript();

	public PyhidraPlugin(PluginTool tool) {
		super(tool);
		GhidraState state = new GhidraState(tool, tool.getProject(), null, null, null, null);
		// use the copy constructor so this state doesn't fire plugin events
		script.set(new GhidraState(state), null, null);
	}

	@Override
	public void init() {
		initializer.accept(this);
	}

	@Override
	protected void close() {
		script.close();
		super.close();
	}

	@Override
	public void dispose() {
		finalizer.run();
		super.dispose();
	}

	@Override
	protected void programActivated(Program program) {
		script.setCurrentProgram(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		if (script.getCurrentProgram() == program) {
			script.setCurrentProgram(null);
		}
	}

	@Override
	protected void locationChanged(ProgramLocation location) {
		script.setCurrentLocation(location);
	}

	@Override
	protected void selectionChanged(ProgramSelection selection) {
		script.setCurrentSelection(selection);
	}

	@Override
	protected void highlightChanged(ProgramSelection highlight) {
		script.setCurrentHighlight(highlight);
	}
}
