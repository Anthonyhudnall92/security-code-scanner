#!/usr/bin/env python3
"""
HTML Security Report Generator for Semgrep Results
Generates a clean HTML report with findings, severity levels, and remediation guidance.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# CVE and remediation database for common security issues
SECURITY_GUIDANCE = {
    "secrets": {
        "description": "Secrets detected in code",
        "remediation": [
            "Remove hardcoded secrets from source code",
            "Use environment variables or secure secret management systems",
            "Rotate exposed credentials immediately",
            "Add secrets scanning to CI/CD pipeline"
        ],
        "references": [
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_CheatSheet.html"
        ]
    },
    "security": {
        "description": "Security vulnerability detected",
        "remediation": [
            "Review and validate the security concern",
            "Apply appropriate input validation",
            "Use security best practices for the identified issue",
            "Test the fix thoroughly"
        ],
        "references": [
            "https://owasp.org/www-project-top-ten/",
            "https://cwe.mitre.org/"
        ]
    },
    "injection": {
        "description": "Potential injection vulnerability",
        "remediation": [
            "Use parameterized queries or prepared statements",
            "Validate and sanitize all user input",
            "Apply principle of least privilege",
            "Use ORM frameworks where appropriate"
        ],
        "references": [
            "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
    },
    "xss": {
        "description": "Cross-Site Scripting vulnerability",
        "remediation": [
            "Encode output data before displaying to users",
            "Validate and sanitize all user input",
            "Use Content Security Policy (CSP) headers",
            "Apply context-appropriate encoding"
        ],
        "references": [
            "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
    }
}

def get_severity_color(severity):
    """Get color based on severity level"""
    colors = {
        "ERROR": "#dc3545",    # Red
        "WARNING": "#fd7e14",  # Orange
        "INFO": "#17a2b8",     # Blue
        "HIGH": "#dc3545",     # Red
        "MEDIUM": "#fd7e14",   # Orange
        "LOW": "#28a745"       # Green
    }
    return colors.get(severity.upper(), "#6c757d")  # Default gray

def get_guidance_for_rule(rule_id, message):
    """Get security guidance based on rule ID and message"""
    rule_lower = rule_id.lower()
    message_lower = message.lower()
    
    if "secret" in rule_lower or "password" in rule_lower or "key" in rule_lower:
        return SECURITY_GUIDANCE["secrets"]
    elif "inject" in rule_lower or "inject" in message_lower:
        return SECURITY_GUIDANCE["injection"]
    elif "xss" in rule_lower or "cross-site" in message_lower:
        return SECURITY_GUIDANCE["xss"]
    else:
        return SECURITY_GUIDANCE["security"]

def generate_html_report(json_file, output_file):
    """Generate HTML report from Semgrep JSON results"""
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: JSON file {json_file} not found")
        return False
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {json_file}")
        return False
    
    results = data.get('results', [])
    errors = data.get('errors', [])
    
    # Generate HTML content
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 3px solid #3498db;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #3498db;
        }}
        .summary-card.critical {{ border-left-color: #dc3545; }}
        .summary-card.high {{ border-left-color: #fd7e14; }}
        .summary-card.medium {{ border-left-color: #ffc107; }}
        .summary-card.low {{ border-left-color: #28a745; }}
        .summary-number {{
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .finding {{
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 15px;
            background-color: #f8f9fa;
            border-bottom: 1px solid #ddd;
        }}
        .finding-content {{
            padding: 20px;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.8em;
            text-transform: uppercase;
        }}
        .file-path {{
            font-family: 'Courier New', monospace;
            background-color: #e9ecef;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        .code-snippet {{
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }}
        .remediation {{
            background-color: #e8f5e8;
            border: 1px solid #c3e6c3;
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
        }}
        .remediation h4 {{
            margin-top: 0;
            color: #155724;
        }}
        .remediation ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .references {{
            margin-top: 15px;
        }}
        .references a {{
            color: #007bff;
            text-decoration: none;
            display: block;
            margin: 5px 0;
        }}
        .references a:hover {{
            text-decoration: underline;
        }}
        .no-findings {{
            text-align: center;
            padding: 40px;
            color: #28a745;
        }}
        .no-findings .icon {{
            font-size: 4em;
            margin-bottom: 20px;
        }}
        .timestamp {{
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 40px;
        }}
        .error {{
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 6px;
            padding: 15px;
            margin: 10px 0;
            color: #721c24;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <p>Automated security analysis results</p>
        </div>
        
        <div class="summary">
            <div class="summary-card critical">
                <div class="summary-number">{len([r for r in results if r.get('extra', {}).get('severity') in ['ERROR', 'HIGH']])}</div>
                <div>Critical/High</div>
            </div>
            <div class="summary-card medium">
                <div class="summary-number">{len([r for r in results if r.get('extra', {}).get('severity') == 'MEDIUM'])}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="summary-number">{len([r for r in results if r.get('extra', {}).get('severity') in ['LOW', 'INFO', 'WARNING']])}</div>
                <div>Low/Info</div>
            </div>
            <div class="summary-card">
                <div class="summary-number">{len(results)}</div>
                <div>Total Findings</div>
            </div>
        </div>
"""

    if not results and not errors:
        html_content += """
        <div class="no-findings">
            <div class="icon">✅</div>
            <h2>No Security Issues Found</h2>
            <p>Great! Your code appears to be free of common security vulnerabilities and secrets.</p>
        </div>
        """
    else:
        if errors:
            html_content += "<h2>Scan Errors</h2>\n"
            for error in errors:
                html_content += f"""
                <div class="error">
                    <strong>Error:</strong> {error.get('message', 'Unknown error')}<br>
                    <strong>Location:</strong> {error.get('path', 'Unknown')}
                </div>
                """
        
        if results:
            html_content += "<h2>Security Findings</h2>\n"
            
            for i, result in enumerate(results, 1):
                rule_id = result.get('check_id', 'unknown-rule')
                message = result.get('message', 'No description available')
                severity = result.get('extra', {}).get('severity', 'INFO')
                file_path = result.get('path', 'unknown')
                start_line = result.get('start', {}).get('line', 0)
                end_line = result.get('end', {}).get('line', 0)
                
                # Get security guidance
                guidance = get_guidance_for_rule(rule_id, message)
                
                html_content += f"""
                <div class="finding">
                    <div class="finding-header">
                        <h3>Finding #{i}: {rule_id}</h3>
                        <span class="severity-badge" style="background-color: {get_severity_color(severity)}">{severity}</span>
                        <br>
                        <strong>File:</strong> <span class="file-path">{file_path}</span>
                        <strong>Lines:</strong> {start_line}-{end_line}
                    </div>
                    <div class="finding-content">
                        <h4>Description</h4>
                        <p>{message}</p>
                        
                        <div class="remediation">
                            <h4>🔧 Remediation Steps</h4>
                            <p><strong>{guidance['description']}</strong></p>
                            <ul>
                """
                
                for step in guidance['remediation']:
                    html_content += f"<li>{step}</li>\n"
                
                html_content += """
                            </ul>
                            <div class="references">
                                <h5>📚 References:</h5>
                """
                
                for ref in guidance['references']:
                    html_content += f'<a href="{ref}" target="_blank">{ref}</a>\n'
                
                html_content += """
                            </div>
                        </div>
                    </div>
                </div>
                """

    html_content += f"""
        <div class="timestamp">
            Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
</body>
</html>
"""

    # Write HTML file
    try:
        with open(output_file, 'w') as f:
            f.write(html_content)
        return True
    except Exception as e:
        print(f"Error writing HTML file: {e}")
        return False

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 generate_html_report.py <json_file> <output_html>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if generate_html_report(json_file, output_file):
        print(f"HTML report generated successfully: {output_file}")
    else:
        print("Failed to generate HTML report")
        sys.exit(1)

if __name__ == "__main__":
    main()
