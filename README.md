<a href="https://github.com/marcelkwaschny/pySigma-backend-netwitness/actions/workflows/test.yml?query=branch%3Amain" target="_blank">
    <img src="https://github.com/marcelkwaschny/pySigma-backend-netwitness/actions/workflows/test.yml/badge.svg?branch=main" alt="Test status">
</a>
<a href="https://github.com/marcelkwaschny/pySigma-backend-netwitness/actions/workflows/test.yml?query=branch%3Amain" target="_blank">
    <img src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/marcelkwaschny/67d1a922faf7921cada718e3677c5b51/raw/marcelkwaschny-pySigma-backend-netwitness.json" alt="Test coverage">
</a>
<a href="https://pypi.org/project/pySigma-backend-netwitness" target="_blank">
    <img src="https://img.shields.io/pypi/v/pySigma-backend-netwitness?color=%2334D058&label=pypi%20package" alt="Package version">
</a>
<a href="https://pypi.org/project/pySigma-backend-netwitness" target="_blank">
    <img src="https://img.shields.io/pypi/pyversions/pySigma-backend-netwitness.svg?color=%2334D058" alt="Supported Python versions">
</a>
<a href="https://pypi.org/project/pySigma-backend-netwitness" target="_blank">
    <img src="https://img.shields.io/badge/Status-pre--release-orange" alt="Release status">
</a>

# pySigma NetWitness Backend

This is the NetWitness backend for pySigma. It provides the package `sigma.backends.netwitness` with the `NetWitnessBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.netwitness`:

* netwitness_windows_pipeline: NetWitness mapping and conversions for Windows

This backend is currently maintained by:

* [Marcel Kwaschny](https://github.com/marcelkwaschny/)
* [Nik Stuckenbrock](https://github.com/nikstuckenbrock/)
* [puQy](https://github.com/puQy/)


## Requirements
* <a href="https://github.com/SigmaHQ/pySigma" class="external-link" target="_blank">pySigma</a>

## Installation
```console
pip install pysigma-backend-netwitness
```

## Example
* Create a file `main.py` with:

```Python
from sigma.collection import SigmaCollection
from sigma.backends.netwitness.netwitness import NetWitnessBackend
from sigma.pipelines.netwitness.windows import netwitness_windows_pipeline

netwitness_backend = NetWitnessBackend(processing_pipeline=netwitness_windows_pipeline())

conversion_result: list[str] = netwitness_backend.convert(
    SigmaCollection.from_yaml(
        """
        title: Test
        status: test
        logsource:
            product: windows
            category: process_creation
        detection:
            sel:
                CommandLine: test
            condition: sel
        """
    )
)

print(conversion_result[0])
```

Run the example with:

```console
$ python main.py

reference.id = '4688' && param = 'test'
```