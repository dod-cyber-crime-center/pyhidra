import sys

if __name__ == '__main__':
    print(" ".join(sys.argv))
    print(currentProgram)
    assert currentProgram.name == "strings.exe"
    assert currentProgram.listing
    assert currentProgram.changeable
    assert toAddr(0).offset == 0
    assert monitor is not None
    assert hasattr(__this__, "currentAddress")
    assert currentSelection is None
    assert currentHighlight is None
