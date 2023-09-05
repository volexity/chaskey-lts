# chaskey_lts

A pure Python chaskey cipher implementation developed initially for use with the [donut_decryptor](https://github.com/volexity/donut-decryptor).

## Installation

You can install donut_decryptor for usage by navigating to the root directory of the project and using pip:

```bash
cd /path/to/donut-decryptor
python -m pip install .
```

For usage instructions use the following input at a python prompt:

```bash
> import chaskey

> help(chaskey.Chaskey)
```

## TODO

* Implement non-CTR cipher modes
* Consider a class based definition of cipher modes to replace the current catch-all implementation
