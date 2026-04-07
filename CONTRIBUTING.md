# Contributing to Shield

Thank you for your interest in contributing to Shield! We welcome contributions from everyone.

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/yourusername/shield-prompt-injection.git
   cd shield-prompt-injection
   ```
3. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. **Install in development mode**:
   ```bash
   pip install -e ".[dev]"
   ```

## Development Workflow

### Making Changes

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and add tests

3. **Run tests**:
   ```bash
   pytest tests/ -v
   ```

4. **Format code**:
   ```bash
   black shield/ tests/ examples/
   ```

5. **Lint**:
   ```bash
   flake8 shield/ tests/ examples/
   ```

6. **Type check**:
   ```bash
   mypy shield/
   ```

### Committing

Follow conventional commit messages:
- `feat: Add new detection pattern`
- `fix: Fix false positive in detector`
- `docs: Update README`
- `test: Add tests for sanitizer`
- `refactor: Optimize detection engine`

```bash
git commit -m "feat: Add new detection pattern for X"
```

### Pushing and Creating Pull Request

1. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request** on GitHub with:
   - Clear description of changes
   - Reference to any related issues
   - Screenshot/example if applicable

## Code Guidelines

### Style
- Follow PEP 8
- Use type hints where possible
- Use descriptive variable names
- Add docstrings to functions and classes

### Documentation
- Document public APIs
- Add examples for new features
- Update README if necessary
- Update CHANGELOG.md

### Testing
- Write tests for all new features
- Aim for >80% code coverage
- Test edge cases and error conditions
- Include both positive and negative test cases

Example test structure:
```python
class TestNewFeature(unittest.TestCase):
    def setUp(self):
        """Initialize test fixtures"""
        pass

    def test_feature_basic(self):
        """Test basic functionality"""
        pass

    def test_feature_edge_case(self):
        """Test edge cases"""
        pass

    def test_feature_error(self):
        """Test error handling"""
        pass
```

## Adding Detection Patterns

To add a new detection pattern:

1. Add to `INJECTION_PATTERNS` dict in `shield/detector.py`:
   ```python
   INJECTION_PATTERNS = {
       # ... existing patterns ...
       "new_pattern": r"(?i)(your|regex|here)",
   }
   ```

2. Add test case in `tests/test_shield.py`:
   ```python
   def test_new_pattern(self):
       """Test detection of new pattern"""
       malicious = "Example text with new pattern"
       is_injection, threat_level, details = self.detector.detect(malicious)
       self.assertTrue(is_injection)
   ```

3. Document in README.md

## Reporting Issues

### Bug Reports
Include:
- Python version and OS
- Shield version
- Minimal reproducible example
- Expected vs actual behavior

### Feature Requests
Describe:
- Problem you're trying to solve
- Proposed solution
- Alternative approaches considered
- Potential impact

## Review Process

All pull requests will be reviewed for:
- Code quality and style
- Test coverage
- Documentation
- Security implications
- Performance impact

## Community Guidelines

- Be respectful and inclusive
- Welcome diverse perspectives
- Focus on constructive feedback
- Help others learn and grow

## Questions?

- 📧 Email: your-email@example.com
- 💬 GitHub Discussions: [Link to discussions]
- 🐛 GitHub Issues: [Link to issues]

Thank you for contributing to Shield! 🛡️
