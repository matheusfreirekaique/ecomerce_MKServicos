from setuptools import setup, find_packages

setup(
    name="seu_app",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        'flask',
        'flask-sqlalchemy',
        'gunicorn',
        'psycopg2-binary',
    ],
    entry_points={
        'console_scripts': [
            'flask=flask.cli:main'
        ],
    },
)