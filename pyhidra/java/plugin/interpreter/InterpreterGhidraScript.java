package dc3.pyhidra.plugin.interpreter;

import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * Custom GhidraScript only for use with the interpreter console
 */
public final class InterpreterGhidraScript extends GhidraScript {

	private Runnable closer;

	public InterpreterGhidraScript() {
	}

	public void close() {
		if (closer != null) {
			closer.run();
		}
	}

	void setCloser(Runnable closer) {
		this.closer = closer;
	}

	@Override
	public void run() {
	}

	public Address getCurrentAddress() {
		return currentAddress;
	}

	public ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	public ProgramSelection getCurrentSelection() {
		return currentSelection;
	}

	public ProgramSelection getCurrentHighlight() {
		return currentHighlight;
	}

	public PrintWriter getWriter() {
		return writer;
	}

	public void setCurrentProgram(Program program) {
		currentProgram = program;
		state.setCurrentProgram(program);
	}

	public void setCurrentAddress(Address address) {
		currentAddress = address;
		state.setCurrentAddress(address);
	}

	public void setCurrentLocation(ProgramLocation location) {
		currentLocation = location;
		currentAddress = location != null ? location.getAddress() : null;
		state.setCurrentLocation(location);
	}

	public void setCurrentSelection(ProgramSelection selection) {
		currentSelection = selection;
		state.setCurrentSelection(selection);
	}

	public void setCurrentHighlight(ProgramSelection highlight) {
		currentHighlight = highlight;
		state.setCurrentHighlight(highlight);
	}

	public final void set(GhidraState state, PrintWriter writer) {
		set(state, new InterpreterTaskMonitor(), writer);
	}
}
