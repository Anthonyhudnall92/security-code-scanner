#!/bin/bash

# security-scan-html.sh - Enhanced security scanning script with HTML report generation
# Features: Comprehensive scanning, HTML reports with CVEs and remediation guidance

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCAN_PATH="${1:-.}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
JSON_REPORT="semgrep_results_${TIMESTAMP}.json"
HTML_REPORT="security_report_${TIMESTAMP}.html"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to print banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    🛡️  SECURITY SCANNER                       ║"
    echo "║              Comprehensive Code Security Analysis            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to check dependencies
check_dependencies() {
    echo -e "${YELLOW}🔍 Checking dependencies...${NC}"
    
    # Check if semgrep is installed
    if ! command -v semgrep &> /dev/null; then
        echo -e "${RED}❌ Semgrep is not installed. Please install it first:${NC}"
        echo -e "${YELLOW}   brew install semgrep${NC}"
        exit 1
    fi
    
    # Check if python3 is available
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python 3 is not installed. Please install it first.${NC}"
        exit 1
    fi
    
    # Check if HTML report generator exists
    if [ ! -f "${SCRIPT_DIR}/generate_html_report.py" ]; then
        echo -e "${RED}❌ HTML report generator not found: ${SCRIPT_DIR}/generate_html_report.py${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ All dependencies satisfied${NC}"
}

# Function to run security scan
run_security_scan() {
    echo -e "${YELLOW}🔍 Scanning for security issues in: ${SCAN_PATH}${NC}"
    echo -e "${PURPLE}Running comprehensive security analysis...${NC}"
    
    # Run comprehensive Semgrep scan with multiple rule sets
    semgrep \
        --config=p/secrets \
        --config=p/security-audit \
        --config=p/owasp-top-ten \
        --config=p/cwe-top-25 \
        --config=p/supply-chain \
        --json \
        --verbose \
        "${SCAN_PATH}" > "${JSON_REPORT}" 2>/dev/null
    
    local scan_exit_code=$?
    
    if [ $scan_exit_code -ne 0 ] && [ $scan_exit_code -ne 1 ]; then
        echo -e "${RED}❌ Semgrep scan failed with exit code: ${scan_exit_code}${NC}"
        return 1
    fi
    
    return $scan_exit_code
}

# Function to generate HTML report
generate_html_report() {
    echo -e "${YELLOW}📊 Generating HTML report...${NC}"
    
    python3 "${SCRIPT_DIR}/generate_html_report.py" "${JSON_REPORT}" "${HTML_REPORT}"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ HTML report generated: ${HTML_REPORT}${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed to generate HTML report${NC}"
        return 1
    fi
}

# Function to display summary
display_summary() {
    local scan_exit_code=$1
    
    echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                        📋 SCAN SUMMARY                        ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    # Parse JSON results for summary
    if [ -f "${JSON_REPORT}" ]; then
        local finding_count=$(python3 -c "
import json
try:
    with open('${JSON_REPORT}', 'r') as f:
        data = json.load(f)
    print(len(data.get('results', [])))
except:
    print(0)
")
        
        echo -e "📁 Scanned Path: ${PURPLE}${SCAN_PATH}${NC}"
        echo -e "📄 JSON Report: ${PURPLE}${JSON_REPORT}${NC}"
        echo -e "🌐 HTML Report: ${PURPLE}${HTML_REPORT}${NC}"
        echo -e "🔍 Total Findings: ${PURPLE}${finding_count}${NC}"
        
        if [ $scan_exit_code -eq 0 ] && [ $finding_count -eq 0 ]; then
            echo -e "\n${GREEN}🎉 EXCELLENT! No security issues found!${NC}"
            echo -e "${GREEN}Your code appears to be secure and free of common vulnerabilities.${NC}"
        else
            echo -e "\n${YELLOW}⚠️  Security issues detected!${NC}"
            echo -e "${YELLOW}Please review the HTML report for detailed findings and remediation steps.${NC}"
        fi
    else
        echo -e "${RED}❌ Unable to read scan results${NC}"
    fi
    
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

# Function to open HTML report
open_html_report() {
    if [ -f "${HTML_REPORT}" ]; then
        echo -e "\n${YELLOW}🌐 Opening HTML report in browser...${NC}"
        if command -v open &> /dev/null; then
            open "${HTML_REPORT}"
        elif command -v xdg-open &> /dev/null; then
            xdg-open "${HTML_REPORT}"
        else
            echo -e "${YELLOW}Please open the HTML report manually: ${HTML_REPORT}${NC}"
        fi
    fi
}

# Function to cleanup old reports (optional)
cleanup_old_reports() {
    echo -e "${YELLOW}🧹 Cleaning up old reports...${NC}"
    # Keep only the 5 most recent reports
    find . -name "semgrep_results_*.json" -type f | sort -r | tail -n +6 | xargs rm -f 2>/dev/null
    find . -name "security_report_*.html" -type f | sort -r | tail -n +6 | xargs rm -f 2>/dev/null
}

# Main execution
main() {
    print_banner
    
    # Parse command line arguments
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        echo "Usage: $0 [SCAN_PATH] [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --no-open      Don't automatically open HTML report"
        echo "  --cleanup      Clean up old reports"
        echo ""
        echo "Examples:"
        echo "  $0                    # Scan current directory"
        echo "  $0 /path/to/project   # Scan specific directory"
        echo "  $0 . --no-open        # Scan but don't open report"
        exit 0
    fi
    
    NO_OPEN=false
    DO_CLEANUP=false
    
    for arg in "$@"; do
        case $arg in
            --no-open)
                NO_OPEN=true
                shift
                ;;
            --cleanup)
                DO_CLEANUP=true
                shift
                ;;
        esac
    done
    
    check_dependencies
    
    echo -e "${BLUE}🚀 Starting security scan...${NC}"
    echo -e "📅 Timestamp: $(date)"
    
    # Run the security scan
    run_security_scan
    scan_exit_code=$?
    
    # Generate HTML report
    if generate_html_report; then
        display_summary $scan_exit_code
        
        # Open HTML report unless --no-open is specified
        if [ "$NO_OPEN" = false ]; then
            open_html_report
        fi
        
        # Cleanup old reports if requested
        if [ "$DO_CLEANUP" = true ]; then
            cleanup_old_reports
        fi
        
        echo -e "\n${GREEN}✅ Security scan completed successfully!${NC}"
        exit $scan_exit_code
    else
        echo -e "\n${RED}❌ Security scan completed but HTML report generation failed${NC}"
        exit 1
    fi
}

# Run main function
main "$@"
