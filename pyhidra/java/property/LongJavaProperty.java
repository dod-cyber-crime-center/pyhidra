package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;

public final class LongJavaProperty extends AbstractJavaProperty<Long> {

	LongJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		super(field, getter, setter);
	}

	public long fget(Object self) throws Throwable {
		return doGet(self);
	}
}
