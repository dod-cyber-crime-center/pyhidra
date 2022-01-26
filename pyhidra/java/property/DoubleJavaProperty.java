package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;

public final class DoubleJavaProperty extends AbstractJavaProperty<Double> {

	DoubleJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		super(field, getter, setter);
	}

	public double fget(Object self) throws Throwable {
		return doGet(self);
	}
}
