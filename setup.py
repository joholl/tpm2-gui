# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="tpm2-gui",
    version="0.1",
    author="Johannes Holland",
    author_email="joh.ho@gmx.de",
    description="A TPM TSS Feature API Graphical User Interface",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/joholl/tpm2-gui",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.5',
)