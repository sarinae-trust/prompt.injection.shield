"""
Setup configuration for Shield library
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="shield-prompt-injection",
    version="0.1.0",
    author="Shield Team",
    author_email="your-email@example.com",
    description="A comprehensive library to detect and sanitize prompt injection attacks for LLM applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/shield-prompt-injection",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=22.0",
            "flake8>=4.0",
            "mypy>=0.950",
        ]
    },
    keywords="prompt-injection security llm ai chatgpt gpt protection",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/shield-prompt-injection/issues",
        "Source": "https://github.com/yourusername/shield-prompt-injection",
        "Documentation": "https://github.com/yourusername/shield-prompt-injection/blob/main/README.md",
    },
)
