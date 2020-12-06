# tpm2_gui

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)

<img src="https://github.com/joholl/tpm2_gui/blob/master/resources/tpm.svg" width="10%">

**This is project is at an early development stage. Use at your own risk.**

This is a GUI tool to the Trusted Platform Module (TPM). Specifically,
tpm2_gui provides a user-friendly interface to the [TPM Software Stack
(TSS)](https://github.com/tpm2-software/tpm2-tss) Feature API (FAPI) keystore.

## Dependencies

Required packages:
 * python >= 3.5
 * GTK+ >= 3.0
 * GObject Introspection
 * GdkPixbuf >= 2.0
 * Pango
 * json-c

Required Python packages:
 * tpm2_pytss (**unstable, i.e. install from source**)
 * pyobject3
 * cryptography

## Getting Started

After installing the dependencies, tpm2_gui can be started:

```
tpm2_gui
```

If you're running tpm2_gui from source, try running it as a python module:

```
python -m tpm2_gui
```

## Testing

To be done.

## Contribute

Report bugs, request features and give feedback via a [new
issue](https://github.com/joholl/tpm2_gui/issues/new). Contributions and
feedback welcome!

You can automatically format your code:

```
isort tpm2_gui
black tpm2_gui
```

Before submission, please run the linters to ensure adhering to the coding style:

```
./linters.sh
```

## License

tpm2_gui is distributed under the [BSD 2 Clause License](LICENSE).