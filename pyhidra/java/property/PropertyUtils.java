package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.util.Msg;

public class PropertyUtils {

	private PropertyUtils() {
	}

	public static JavaProperty<?>[] getProperties(Class<?> cls) {
		try {
			return doGetProperties(cls);
		}
		catch (Throwable t) {
			Msg.error(PropertyUtils.class,
				"Failed to extract properties for " + cls.getSimpleName(), t);
			return new JavaProperty<?>[0];
		}
	}

	private static JavaProperty<?>[] doGetProperties(Class<?> cls) throws Throwable {
		PropertyPairFactory factory;
		try {
			factory = new PropertyPairFactory(cls);
		}
		catch (IllegalArgumentException e) {
			// skip illegal lookup class
			return new JavaProperty<?>[0];
		}
		return getMethods(cls)
				.filter(PropertyUtils::methodFilter)
				.map(PropertyUtils::toProperty)
				.flatMap(Optional::stream)
				.collect(
					Collectors.groupingBy(
						PartialProperty::getName))
				.values()
				.stream()
				.map(factory::merge)
				.flatMap(Optional::stream)
				.toArray(JavaProperty<?>[]::new);
	}

	private static Stream<Method> getMethods(Class<?> cls) {
		if (isPublic(cls)) {
			return Arrays.stream(cls.getMethods());
		}
		Class<?> base = cls;
		while (!isPublic(base)) {
			base = base.getSuperclass();
		}
		Stream<Method> head = Arrays.stream(base.getMethods())
				.filter(PropertyUtils::methodFilter);
		Stream<Method> tail = Stream.concat(
			Arrays.stream(base.getInterfaces()),
			Arrays.stream(cls.getInterfaces()))
				.sorted(Comparator.comparing(Class::getSimpleName))
				.distinct()
				.map(Class::getDeclaredMethods)
				.flatMap(Arrays::stream)
				.filter(PropertyUtils::methodFilter);
		return Stream.concat(head, tail)
				.sorted(Comparator.comparing(Method::toGenericString))
				.distinct();
	}

	private static boolean methodFilter(Method m) {
		return isPublic(m) && (m.getName().charAt(0) & 'a') == 'a' && m.getParameterCount() < 2;
	}

	private static boolean isPublic(Class<?> cls) {
		return Modifier.isPublic(cls.getModifiers());
	}

	private static boolean isPublic(Method m) {
		int mod = m.getModifiers();
		return Modifier.isPublic(mod) && !Modifier.isStatic(mod);
	}

	private static class PropertyPairFactory {
		private final Lookup lookup;

		private PropertyPairFactory(Class<?> c) {
			lookup = MethodHandles.publicLookup();
		}

		private Optional<JavaProperty<?>> merge(List<PartialProperty> pairs) {
			try {
				if (pairs.size() == 1) {
					PartialProperty p = pairs.get(0);
					MethodHandle h = lookup.unreflect(p.m);
					JavaProperty<?> res = p.isGetter() ? JavaPropertyFactory.get(p.name, h, null)
							: JavaPropertyFactory.get(p.name, null, h);
					return Optional.of(res);
				}
				PartialProperty g = pairs.stream()
						.filter(PartialProperty::isGetter)
						.findFirst()
						.orElse(null);
				if (g != null) {
					Class<?> target = g.m.getReturnType();
					PartialProperty s = pairs.stream()
							.filter(PartialProperty::isSetter)
							.filter(p -> p.m.getParameterTypes()[0] == target)
							.findFirst()
							.orElse(null);
					MethodHandle gh = lookup.unreflect(g.m);
					MethodHandle sh = s != null ? lookup.unreflect(s.m) : null;
					return Optional.of(JavaPropertyFactory.get(g.name, gh, sh));
				}
			}
			catch (IllegalAccessException e) {
				// this is a class in java.lang.invoke or java.lang.reflect
				// the JVM doesn't allow the creation of handles for these
			}
			// multiple setters. ie not a property
			return Optional.empty();
		}
	}

	private static Optional<PartialProperty> toProperty(Method m) {
		String name = m.getName();
		int n = m.getParameterCount();
		try {
			switch ((name.charAt(0) ^ 'a') >> 2) {
				case 1: // g
					if (!name.startsWith("get")) {
						return Optional.empty();
					}
					if (n != 0 || m.getReturnType() == Void.TYPE) {
						return Optional.empty();
					}
					name = name.substring(3);
					break;
				case 2: // i
					if (!name.startsWith("is")) {
						return Optional.empty();
					}
					if (n != 0 || m.getReturnType() != Boolean.TYPE) {
						return Optional.empty();
					}
					name = name.substring(2);
					break;
				case 4: // s
					if (!name.startsWith("set")) {
						return Optional.empty();
					}
					if (n != 1 || m.getReturnType() != Void.TYPE) {
						return Optional.empty();
					}
					name = name.substring(3);
					break;
				default:
					return Optional.empty();
			}
			if (Character.isLowerCase(name.charAt(0))) {
				return Optional.empty();
			}
			char c = Character.toLowerCase(name.charAt(0));
			name = c + name.substring(1);
			return Optional.of(new PartialProperty(m, name));
		}
		catch (IndexOutOfBoundsException e) {
			// probability is extremely small
			return Optional.empty();
		}
	}

	private static class PartialProperty {
		private final Method m;
		private final String name;

		private PartialProperty(Method m, String name) {
			this.m = m;
			this.name = name;
		}

		public boolean isGetter() {
			return m.getParameterCount() == 0 && m.getReturnType() != Void.TYPE;
		}

		public boolean isSetter() {
			return m.getParameterCount() == 1 && m.getReturnType() == Void.TYPE;
		}

		public String getName() {
			return name;
		}
	}
}
