from setuptools import setup, find_packages

setup(
    name="wpsscanner",
    version="0.1.0",
    description="WPS Path Scanner",
    packages=find_packages(where="src"),
    package_dir={"": "src"},

    entry_points={
        "console_scripts": [
            "wpsscanner = wpsscanner.cli:main",
        ]
    },

    python_requires=">=3.8",
)
