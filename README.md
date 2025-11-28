# chaskey_lts

A pure Python chaskey cipher implementation developed initially for use with the [donut_decryptor](https://github.com/volexity/donut-decryptor).

## Installation

You can install donut_decryptor for usage using pip:

```bash
python -m pip install chaskey
```

For usage instructions use the following input at a python prompt:

```bash
> import chaskey

> help(chaskey.Chaskey)
```

## TODO

* Implement non-CTR cipher modes
  * Electronic Code Book (ECB)
  * Cipher Block Chain (CBC)
  * Cipher Feedback Mode (CFB)
  * Output Feedback Mode (OFB)
  * Galois Counter Mode (GCM)
* Consider a class based definition of cipher modes to replace the current catch-all implementation
