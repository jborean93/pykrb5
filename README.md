# Python Kerberos 5 Library

Info here

```bash
poetry run ./build.py --for-sdist
poetry build --format sdist -vvv
rm __dont_use_cython__.txt

poetry build --format wheel -vvv
```

Running tests and vscode development
```bash
python setup.py build_ext --inplace
```