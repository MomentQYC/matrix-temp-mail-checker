from setuptools import setup, find_packages

__version__ = "0.1.2"

with open("README.md") as f:
    long_description = f.read()

setup(
    name="matrix-temp-mail-checker",
    version=__version__,
    packages=find_packages(),
    install_requires=["matrix-synapse>=1.37.0"],
    description="A Synapse spam checker module to block temp email domains.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="MomentQYC",
    url="https://github.com/MomentQYC/matrix-temp-mail-checker",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
