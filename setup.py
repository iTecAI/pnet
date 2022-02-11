import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="peernet",
    version="0.1.0",
    author="Dax Harris",
    description="Local encrypted p2p communication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/iTecAI/pnet",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        'rsa',
        'cryptography'
    ],
    keywords='p2p peer socket encryption',
    project_urls={
        'Homepage': 'https://github.com/iTecAI/pnet',
    }
)
