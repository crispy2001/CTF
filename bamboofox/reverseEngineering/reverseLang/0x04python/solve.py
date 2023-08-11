import dis

with open("py.cpython-38.pyc", "rb") as f:
    code = f.read()

dis.dis(code)

