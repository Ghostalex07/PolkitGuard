from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="polkitguard",
    version="1.18.0",
    author="Ghostalex07",
    author_email="ghostalex07@example.com",
    description="Security scanner for Linux Polkit policies",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Ghostalex07/PolkitGuard",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "polkitguard=polkitguard.cli:main",
        ],
    },
    include_package_data=True,
)