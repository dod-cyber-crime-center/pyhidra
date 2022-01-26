package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;

public class ObjectJavaProperty extends AbstractJavaProperty<Object> {

	protected ObjectJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		super(field, getter, setter);
	}

	public final Object fget(Object self) throws Throwable {
		return doGet(self);
	}
}
