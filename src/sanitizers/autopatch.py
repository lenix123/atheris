"""
Для обычного (не форкнутого) Atheris: достаточно одной строки

    import sanitizers.autopatch

перед использованием atheris. В форке не нужно — `import atheris`
делает то же самое сам.
"""

import atheris

from .atheris_glue import install_into

install_into(atheris)
