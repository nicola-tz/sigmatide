#!/usr/bin/env python3
"""
Test script for Sigma to OpenTide Converter
"""

import sys
import tempfile
from pathlib import Path

def test_basic_functionality():
    """Test basic converter functionality"""
    print("Testing Sigma to OpenTide Converter...")
    
    try:
        from sigma_opentide_converter import SigmaToOpenTideConverter
        print("✓ Package import successful")
    except ImportError as e:
        print(f"✗ Package import failed: {e}")
        return False
    
    # Test with the existing test rule
    test_rule_path = Path(__file__).parent / "test_sigma_rule.yaml"
    
    if not test_rule_path.exists():
        print(f"✗ Test rule not found: {test_rule_path}")
        return False
    
    try:
        converter = SigmaToOpenTideConverter()
        print("✓ Converter initialization successful")
    except Exception as e:
        print(f"✗ Converter initialization failed: {e}")
        return False
    
    try:
        # Test parsing
        sigma_rule = converter.parse_sigma_rule(str(test_rule_path))
        print(f"✓ Rule parsing successful: '{sigma_rule.title}'")
    except Exception as e:
        print(f"✗ Rule parsing failed: {e}")
        return False
    
    try:
        # Test conversion
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_file:
            output_path = temp_file.name
        
        success = converter.convert_file(str(test_rule_path), output_path)
        
        if success:
            print("✓ File conversion successful")
            print(f"  Output written to: {output_path}")
            
            # Verify output exists and has content
            output_file = Path(output_path)
            if output_file.exists() and output_file.stat().st_size > 0:
                print("✓ Output file contains data")
                
                # Show a preview
                with open(output_path, 'r') as f:
                    lines = f.readlines()[:10]
                    print("  Preview (first 10 lines):")
                    for line in lines:
                        print(f"    {line.rstrip()}")
                
                return True
            else:
                print("✗ Output file is empty or doesn't exist")
                return False
        else:
            print("✗ File conversion failed")
            return False
            
    except Exception as e:
        print(f"✗ Conversion test failed: {e}")
        return False

def main():
    """Main test function"""
    print("=" * 60)
    print("Sigma to OpenTide Converter - Test Suite")
    print("=" * 60)
    
    success = test_basic_functionality()
    
    print("\n" + "=" * 60)
    if success:
        print("✓ All tests passed! The converter is working correctly.")
        print("\nNext steps:")
        print("1. Install the package: pip install -e .")
        print("2. Test the CLI: sigma-opentide check-dependencies")
        print("3. Convert a rule: sigma-opentide convert test_sigma_rule.yaml output.yaml")
    else:
        print("✗ Some tests failed. Check the error messages above.")
        sys.exit(1)
    print("=" * 60)

if __name__ == "__main__":
    main()