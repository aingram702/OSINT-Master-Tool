# Contributing to OSINT Master Tool

Thank you for your interest in contributing! Here's how you can help.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/osint-master-tool.git
   cd osint-master-tool
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Install dependencies**:
   ```bash
   pip install -r MasterToolDir/requirements.txt
   ```
5. **Run the app** to verify your setup:
   ```bash
   python MasterToolDir/app.py
   ```

## How to Contribute

### Adding a New Tool

To add a new external OSINT tool:

1. **Add the tool installation** to `SubTools/` under the appropriate category directory.
2. **Define the tool config** in `MasterToolDir/tool_configs.py`:
   - Add an entry to the `TOOLS` dict with a unique `id`
   - Specify the `category`, `executable`, `script`, `cwd`, and `args`
   - Each arg needs `id`, `label`, `type`, and optionally `flag`, `default`, `help`, etc.
3. **Test** that the tool runs correctly from the UI.

### Adding a Built-in Tool

1. **Implement the handler** in `MasterToolDir/app.py` following the `_builtin_*` pattern.
2. **Register it** in the `BUILTIN_HANDLERS` dict.
3. **Add the config** in `tool_configs.py` with `"builtin": True`.
4. **Add result rendering** in `static/js/app.js` inside `renderBuiltinResult()`.

### Bug Fixes & Improvements

- Check existing [issues](https://github.com/aingram702/osint-master-tool/issues) before creating a new one
- Reference the issue number in your PR description

## Code Style

- **Python**: Follow PEP 8. Use descriptive variable names. Add docstrings to functions.
- **JavaScript**: Use `"use strict"`. Follow the existing IIFE pattern. Use `escapeHtml()` and `escapeAttr()` for all dynamic content.
- **CSS**: Use CSS custom properties from the existing design system. Follow the section comment structure.

## Security Guidelines

- **Never commit secrets**: API keys, `.master.key`, `.env` files must stay out of version control.
- **Validate all user input**: Use the existing regex validators and `is_safe_path()`.
- **Sanitize output**: Always use `escapeHtml()` in the frontend and avoid `innerHTML` with unsanitized data.
- **Log, don't expose errors**: Use `logger.exception()` server-side; return generic messages to clients.

## Pull Request Process

1. Ensure your branch is up-to-date with `main`
2. Test your changes locally
3. Write a clear PR description explaining **what** and **why**
4. Reference any related issues

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
