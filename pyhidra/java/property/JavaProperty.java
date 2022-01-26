package dc3.pyhidra.property;

public interface JavaProperty<T> {

	public abstract void fset(Object self, T value) throws Throwable;
}
