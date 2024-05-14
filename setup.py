from setuptools import setup, find_packages

setup(
    name='malicious_can_bus_detector',
    version='1.0',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    author='Lucas Paiva and Maria Bezerra',
    # description='',
)