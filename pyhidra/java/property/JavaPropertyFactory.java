package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;
import java.util.IdentityHashMap;
import java.util.Map;

class JavaPropertyFactory {

	private static final IdentityHashMap<Class<?>, JavaPropertyBuilder> PROPERTIES =
		new IdentityHashMap<>(
			Map.of(
				Boolean.TYPE, BooleanJavaProperty::new,
				Byte.TYPE, ByteJavaProperty::new,
				Character.TYPE, CharacterJavaProperty::new,
				Double.TYPE, DoubleJavaProperty::new,
				Float.TYPE, FloatJavaProperty::new,
				Integer.TYPE, IntegerJavaProperty::new,
				Long.TYPE, LongJavaProperty::new,
				Short.TYPE, ShortJavaProperty::new));

	private JavaPropertyFactory() {
	}

	static JavaProperty<?> get(String field, MethodHandle getter, MethodHandle setter) {
		Class<?> cls =
			getter != null ? getter.type().returnType() : setter.type().lastParameterType();
		return cls.isPrimitive() ? PROPERTIES.get(cls).build(field, getter, setter)
				: new ObjectJavaProperty(field, getter, setter);
	}

	@FunctionalInterface
	private static interface JavaPropertyBuilder {

		AbstractJavaProperty<?> build(String field, MethodHandle getter, MethodHandle setter);
	}

}
