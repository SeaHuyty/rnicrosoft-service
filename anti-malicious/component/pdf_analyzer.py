import re
import os
from pathlib import Path

class PDFSecurityAnalyzer:
    def __init__(self):
        self.malicious_patterns = [
            (r'file:///C:/windows/system32/cmd\.exe', "Attempts to execute cmd.exe"),
            (r'file:///C:/windows/system32/powershell\.exe', "Attempts to execute PowerShell"),
            (r'/URI\s*\(.*\.exe\)', "Executable file in URI"),
            (r'/JavaScript', "PDF contains JavaScript"),
            (r'/Launch', "PDF launch action"),
        ]
    
    def analyze_pdf(self, pdf_path):
        """Analyze PDF for malicious content (like in pdf.py)"""
        if not os.path.exists(pdf_path):
            return {"safe": True, "message": "File not found"}
        
        try:
            with open(pdf_path, 'rb') as f:
                content = f.read(5000)  # Read first 5KB
                content_str = content.decode('latin-1', errors='ignore')
                
                findings = []
                for pattern, description in self.malicious_patterns:
                    if re.search(pattern, content_str, re.IGNORECASE):
                        findings.append(description)
                
                if findings:
                    return {
                        "safe": False,
                        "message": "Potentially malicious PDF detected",
                        "findings": findings,
                        "risk_score": len(findings) * 25
                    }
                else:
                    return {"safe": True, "message": "PDF appears safe"}
                    
        except Exception as e:
            return {"safe": False, "message": f"Analysis error: {str(e)}"}

# Usage - only run if executed directly
if __name__ == "__main__":
    analyzer = PDFSecurityAnalyzer()
    result = analyzer.analyze_pdf("social_engineering.pdf")
    print(result)