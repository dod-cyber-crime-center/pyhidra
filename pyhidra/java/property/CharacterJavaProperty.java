package dc3.pyhidra.property;

import java.lang.invoke.MethodHandle;

public final class CharacterJavaProperty extends AbstractJavaProperty<Character> {

	CharacterJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		super(field, getter, setter);
	}

	public char fget(Object self) throws Throwable {
		return doGet(self);
	}
}
