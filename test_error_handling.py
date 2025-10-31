#!/usr/bin/env python3
"""
Test script to demonstrate the new error handling for failed query generation
"""

from sigma_opentide_converter.converter import SigmaToOpenTideConverter

def test_conversion_with_failure():
    """Test conversion when one query generation fails"""
    converter = SigmaToOpenTideConverter()
    
    # Test with the sample rule that has Defender failure
    input_file = "test_sigma_rule.yaml"
    output_file = "test_error_handling_output.yaml"
    
    print("=" * 70)
    print("Testing conversion with query generation failure handling")
    print("=" * 70)
    print()
    
    success, generation_status = converter.convert_file(
        input_file,
        output_file,
        target_systems=['defender_for_endpoint', 'splunk'],
        interactive=True  # Will prompt if failures occur
    )
    
    print()
    print("=" * 70)
    print("Conversion Results:")
    print(f"  Overall success: {success}")
    print(f"  Generation status:")
    for system, status in generation_status.items():
        status_icon = "✓" if status else "✗"
        print(f"    {status_icon} {system}: {'Success' if status else 'Failed'}")
    print("=" * 70)

if __name__ == "__main__":
    test_conversion_with_failure()
