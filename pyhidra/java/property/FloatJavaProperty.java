package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;

public final class FloatJavaProperty extends AbstractJavaProperty<Float> {

	FloatJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		super(field, getter, setter);
	}

	public float fget(Object self) throws Throwable {
		return doGet(self);
	}
}
