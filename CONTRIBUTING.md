# CONTRIBUTING Guide

## Contributing to VoIP Security Assessment Framework

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and professional
- Focus on security best practices
- Maintain ethical standards
- Report security issues privately

## Getting Started

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Write/update tests
5. Commit with clear messages
6. Push to your branch
7. Create a Pull Request

## Development Setup

```bash
git clone https://github.com/hydropy1214/Voip.git
cd Voip
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Code Style

- Use PEP 8
- Run `black` for formatting
- Run `flake8` for linting
- Add type hints
- Document with docstrings

```bash
black modules/
flake8 modules/
mypy modules/
```

## Testing

All new code must have tests:

```bash
python -m pytest tests/ -v --cov=modules/
```

## Adding New CVEs

To add a new CVE to the registry:

1. Add entry to `modules/exploits/cve_registry.py`
2. Create exploitation method in platform-specific module
3. Add test case
4. Update documentation

```python
CVEDefinition(
    cve_id="CVE-XXXX-XXXXX",
    title="Vulnerability Title",
    description="Detailed description",
    platforms=[Platform.YOUR_PLATFORM],
    severity=Severity.HIGH,
    cvss_score=7.5,
    published_date="YYYY-MM-DD",
    affected_versions=["1.0", "1.1"],
    detection_method="http|sip|socket",
    detection_endpoint="/path/endpoint",
    detection_payload="payload",
    remediation="Fix instructions",
    references=["https://nvd.nist.gov/..."]
)
```

## Adding New Platforms

1. Add to `Platform` enum in `cve_registry.py`
2. Create `modules/exploits/platform_name_exploit.py`
3. Implement platform-specific vulnerabilities
4. Register in `PLATFORM_MAPPING` in `scanner.py`
5. Add tests

## Documentation

- Keep README.md updated
- Add docstrings to all functions
- Update docs/ for major features
- Include examples

## Pull Request Process

1. Update documentation
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Request review

## Reporting Issues

- Use GitHub Issues
- Include reproduction steps
- Provide system information
- Be clear and concise

## Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead, email: hydropy1214@gmail.com

Include:
- CVE number (if available)
- Detailed description
- Steps to reproduce
- Potential impact

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Feel free to open an issue or discussion for questions.
