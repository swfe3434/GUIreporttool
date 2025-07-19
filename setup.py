import setuptools
import os

def read_requirements():
    """Reads the requirements from requirements.txt."""
    with open('requirements.txt', 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def read_readme():
    """Reads the content of the README.md file."""
    with open('README.md', 'r', encoding='utf-8') as f:
        return f.read()

setuptools.setup(
    name="instareportbot",
    version="0.1.0",
    author="Your Name", # Replace with your name
    author_email="your.email@example.com", # Replace with your email
    description="An educational CLI tool for Instagram automation patterns.",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/instareportbot-project", # Replace with your project URL
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License", # Assuming MIT license based on common open source projects
        "Operating System :: OS Independent",
    ],
    # For a single script at the root, use py_modules
    py_modules=['instabot_cli'],
    install_requires=read_requirements(),
    python_requires=">=3.9",
    entry_points={
        'console_scripts': [
            'instareportbot = instabot_cli:main',
        ],
    },
)
