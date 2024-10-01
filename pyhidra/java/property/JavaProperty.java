package dc3.pyhidra.property;

public interface JavaProperty<T> {

	// this doesn't have fget so that the primitive properties can return a primitive
	// the implementations abuse auto boxing/unboxing and Python's duck typing
	// to create properties for Java primitives
	
	public abstract void fset(Object self, T value) throws Throwable;
}
