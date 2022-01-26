package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;

abstract class AbstractJavaProperty<T> implements JavaProperty<T> {

	public final String field;
	private final MethodHandle getter;
	private final MethodHandle setter;

	protected AbstractJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		this.field = field;
		this.getter = getter;
		this.setter = setter;
	}

	public boolean hasGetter() {
		return getter != null;
	}

	public boolean hasSetter() {
		return setter != null;
	}

	protected final T doGet(Object self) throws Throwable {
		return (T) getter.invoke(self);
	}

	@Override
	public final void fset(Object self, T value) throws Throwable {
		setter.invoke(self, value);
	}
}
