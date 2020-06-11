import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="openconnect-pulse-gui",
    author="Kyle Birkeland",
    author_email="kylebirkeland@gmail.com",
    description="Allows openconnect web-based authentication for Pulse Secure Connect appliances",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/utknoxville/openconnect-pulse-gui",
    packages=setuptools.find_packages(),
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    install_requires=["pygobject"],
    entry_points={
        "console_scripts": ["openconnect-pulse-gui = openconnect_pulse_gui:main",]
    },
)
