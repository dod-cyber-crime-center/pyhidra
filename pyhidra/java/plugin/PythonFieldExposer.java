package dc3.pyhidra.plugin;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.invoke.ConstantBootstraps;
import java.lang.invoke.VarHandle;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.Constructor;
import java.util.Collections;
import java.util.Map;

import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

public interface PythonFieldExposer {
	// marker interface

	public static Map<String, ExposedField> getProperties(
			Class<? extends PythonFieldExposer> cls) {
		try {
			return doGetProperties(cls);
		}
		catch (Throwable t) {
			Msg.error(PythonFieldExposer.class,
				"Failed to expose fields for " + cls.getSimpleName(), t);
			return Collections.emptyMap();
		}
	}

	@SuppressWarnings("unchecked")
	public static Map<String, ExposedField> doGetProperties(
			Class<? extends PythonFieldExposer> cls)
			throws Throwable {
		ExposedFields fields = cls.getAnnotation(ExposedFields.class);
		String[] names = fields.names();
		Class<?>[] types = fields.types();
		if (names.length != types.length) {
			throw new AssertException("Improperly applied ExposedFields on " + cls.getSimpleName());
		}
		Constructor<? extends ExposedField> c =
			fields.exposer().getConstructor(String.class, Class.class);
		Map.Entry<String, ExposedField>[] properties = new Map.Entry[names.length];
		for (int i = 0; i < names.length; i++) {
			properties[i] = Map.entry(names[i], c.newInstance(names[i], types[i]));
		}
		return Map.ofEntries(properties);
	}

	// this annotation is for creating properties to provide access
	// to the protected GhidraScript fields only within a Python script
	@Target(ElementType.TYPE)
	@Retention(RetentionPolicy.RUNTIME)
	public static @interface ExposedFields {
		public Class<? extends ExposedField> exposer();

		public String[] names();

		public Class<?>[] types();
	}

	public static abstract class ExposedField {
		private final VarHandle handle;

		protected ExposedField(Lookup lookup, String name, Class<?> type) {
			handle = ConstantBootstraps.fieldVarHandle(lookup, name, VarHandle.class,
				lookup.lookupClass(), type);
		}

		public Object fget(Object self) {
			return handle.get(self);
		}

		public void fset(Object self, Object value) {
			handle.set(self, value);
		}
	}
}
