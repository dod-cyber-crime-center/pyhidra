package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;

public final class ByteJavaProperty extends AbstractJavaProperty<Byte> {

	ByteJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		super(field, getter, setter);
	}

	public byte fget(Object self) throws Throwable {
		return doGet(self);
	}
}
