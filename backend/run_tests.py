#!/usr/bin/env python3
"""
Test Runner Script

This script runs the comprehensive test suite with coverage reporting
and generates detailed test reports.
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def run_tests(test_type='all', coverage=True, verbose=False):
    """
    Run tests with specified parameters
    
    Args:
        test_type: Type of tests to run (unit, integration, security, all)
        coverage: Whether to generate coverage report
        verbose: Whether to run in verbose mode
    """
    
    # Build pytest command
    cmd = ['python', '-m', 'pytest']
    
    # Add test type filter
    if test_type != 'all':
        cmd.extend(['-m', test_type])
    
    # Add coverage options
    if coverage:
        cmd.extend([
            '--cov=backend',
            '--cov-report=html',
            '--cov-report=term-missing',
            '--cov-fail-under=95',
            '--cov-branch'
        ])
    
    # Add verbosity
    if verbose:
        cmd.append('--verbose')
    
    # Add output file
    cmd.extend([
        '--junit-xml=test-results.xml',
        '--html=test-report.html'
    ])
    
    # Add test directory
    cmd.append('tests/')
    
    # Set environment variables
    env = os.environ.copy()
    env['TESTING'] = 'true'
    env['COVERAGE_PROCESS_START'] = 'true'
    
    print(f"Running tests: {' '.join(cmd)}")
    
    try:
        # Run tests
        result = subprocess.run(
            cmd,
            env=env,
            cwd=Path(__file__).parent,
            capture_output=True,
            text=True
        )
        
        # Print output
        if result.stdout:
            print(result.stdout)
        
        if result.stderr:
            print(f"Errors: {result.stderr}")
        
        # Return exit code
        return result.returncode
        
    except Exception as e:
        print(f"Error running tests: {str(e)}")
        return 1

def check_coverage():
    """Check if coverage meets requirements"""
    try:
        # Parse coverage report
        with open('htmlcov/index.html', 'r') as f:
            content = f.read()
            
        # Look for coverage percentage
        import re
        coverage_match = re.search(r'(\d+\.?\d*)%', content)
        
        if coverage_match:
            coverage_pct = float(coverage_match.group(1))
            print(f"Test coverage: {coverage_pct}%")
            
            if coverage_pct >= 95.0:
                print("✅ Coverage requirement met (≥95%)")
                return True
            else:
                print("❌ Coverage requirement not met (<95%)")
                return False
        else:
            print("❌ Could not determine coverage percentage")
            return False
            
    except FileNotFoundError:
        print("❌ Coverage report not found")
        return False
    except Exception as e:
        print(f"❌ Error checking coverage: {str(e)}")
        return False

def generate_test_report():
    """Generate comprehensive test report"""
    try:
        report = {
            'timestamp': subprocess.run(['date'], capture_output=True, text=True).stdout.strip(),
            'test_results': 'test-results.xml',
            'coverage_report': 'htmlcov/index.html',
            'summary': {}
        }
        
        # Count tests from JUnit XML
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse('test-results.xml')
            root = tree.getroot()
            
            total_tests = 0
            failures = 0
            errors = 0
            skipped = 0
            
            for testcase in root.iter('testcase'):
                total_tests += 1
                
                for child in testcase:
                    if child.tag == 'failure':
                        failures += 1
                    elif child.tag == 'error':
                        errors += 1
                    elif child.tag == 'skipped':
                        skipped += 1
            
            report['summary'] = {
                'total_tests': total_tests,
                'passed': total_tests - failures - errors - skipped,
                'failures': failures,
                'errors': errors,
                'skipped': skipped,
                'success_rate': ((total_tests - failures - errors - skipped) / total_tests * 100) if total_tests > 0 else 0
            }
            
        except Exception as e:
            print(f"Warning: Could not parse test results: {str(e)}")
        
        # Write report
        with open('test-summary.json', 'w') as f:
            import json
            json.dump(report, f, indent=2)
        
        print(f"Test report generated: test-summary.json")
        return True
        
    except Exception as e:
        print(f"Error generating test report: {str(e)}")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Run enterprise authentication tests')
    
    parser.add_argument(
        '--type',
        choices=['unit', 'integration', 'security', 'all'],
        default='all',
        help='Type of tests to run'
    )
    
    parser.add_argument(
        '--no-coverage',
        action='store_true',
        help='Disable coverage reporting'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Run in verbose mode'
    )
    
    parser.add_argument(
        '--check-coverage',
        action='store_true',
        help='Check if coverage meets requirements'
    )
    
    parser.add_argument(
        '--generate-report',
        action='store_true',
        help='Generate comprehensive test report'
    )
    
    args = parser.parse_args()
    
    # Run tests
    coverage = not args.no_coverage
    exit_code = run_tests(
        test_type=args.type,
        coverage=coverage,
        verbose=args.verbose
    )
    
    # Check coverage if requested
    if args.check_coverage and coverage:
        coverage_ok = check_coverage()
        if not coverage_ok:
            exit_code = 1
    
    # Generate report if requested
    if args.generate_report:
        generate_test_report()
    
    # Print summary
    if exit_code == 0:
        print("✅ All tests passed!")
    else:
        print(f"❌ Tests failed with exit code: {exit_code}")
    
    return exit_code

if __name__ == '__main__':
    sys.exit(main())