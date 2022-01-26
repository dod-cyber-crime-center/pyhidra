package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;

public final class BooleanJavaProperty extends AbstractJavaProperty<Boolean> {

	BooleanJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		super(field, getter, setter);
	}

	public boolean fget(Object self) throws Throwable {
		return doGet(self);
	}
}
