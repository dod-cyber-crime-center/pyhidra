package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;

public final class IntegerJavaProperty extends AbstractJavaProperty<Integer> {

	IntegerJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		super(field, getter, setter);
	}

	public int fget(Object self) throws Throwable {
		return doGet(self);
	}
}
