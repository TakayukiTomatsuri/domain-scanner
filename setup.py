from setuptools import setup

setup(
    name="dscanner",
    version="1.0.0",
    install_requires=["requests", "qrcode", "tldextract", "beautifulsoup4", "gglsbl", "tqdm"],
    entry_points={
        "console_scripts": [
            "dscan=dscanner.console_script:main",
        ],
    }
)
