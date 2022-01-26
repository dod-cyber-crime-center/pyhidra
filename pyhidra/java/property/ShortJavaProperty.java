package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;

public final class ShortJavaProperty extends AbstractJavaProperty<Short> {

	ShortJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		super(field, getter, setter);
	}

	public short fget(Object self) throws Throwable {
		return doGet(self);
	}
}
