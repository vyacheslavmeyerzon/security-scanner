#!/bin/bash
# Script to publish git-security-scanner to PyPI

set -e  # Exit on error

echo "🔧 Git Security Scanner - Publishing Script"
echo "=========================================="

# Check if we're in the right directory
if [ ! -f "setup.py" ]; then
    echo "❌ Error: setup.py not found. Please run from project root."
    exit 1
fi

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf build/ dist/ src/*.egg-info

# Run tests
echo "🧪 Running tests..."
pytest tests/ -v

# Check code quality
echo "📝 Checking code quality..."
black --check src tests
flake8 src tests
mypy src

# Build the package
echo "📦 Building package..."
python -m build

# Check the package
echo "🔍 Checking package..."
twine check dist/*

# Display package contents
echo "📋 Package contents:"
tar -tzf dist/*.tar.gz | head -20

echo ""
echo "✅ Package built successfully!"
echo ""
echo "📦 Distribution files:"
ls -la dist/

echo ""
echo "Next steps:"
echo "1. Test installation: pip install dist/*.whl"
echo "2. Upload to Test PyPI: twine upload --repository testpypi dist/*"
echo "3. Test from Test PyPI: pip install --index-url https://test.pypi.org/simple/ git-security-scanner"
echo "4. Upload to PyPI: twine upload dist/*"
echo ""
echo "🚀 Ready to publish!"