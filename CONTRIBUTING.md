# Contributing to AI-Based Junior SOC

Thank you for your interest in contributing to the AI-Based Junior SOC project! We welcome contributions from the community to help make this tool more robust and useful.

## Local Environment Setup
1. **Fork and Clone:** Fork the repository and clone it to your local machine.
2. **Virtual Environment:** We recommend using a virtual environment.
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Environment Variables:** Create a `.env` file based on `.env.example`.

## Coding Guidelines
- **Logging:** Use the `logger` from `app/main.py` instead of `print()`.
- **Placeholder Safety:** Never commit real API keys or internal IP addresses.
- **Style:** Follow PEP 8 guidelines for Python code.
- **Modularization:** Keep functions small and focused on a single task.

## Pull Request Process
1. Create a new branch for your feature or bug fix.
2. Ensure your changes are well-documented.
3. Submit a Pull Request with a clear description of the changes.

## License
By contributing, you agree that your contributions will be licensed under the MIT License.
