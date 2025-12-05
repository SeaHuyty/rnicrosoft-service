#!/usr/bin/env python3
"""
ISO File Scanner - Simple Web Interface
Upload and check ISO files against malicious hash database
"""

import os
import sys
import sqlite3
import hashlib
import threading
from flask import Flask, request, jsonify, render_template_string
from werkzeug.utils import secure_filename

# ================= CONFIGURATION =================
CONFIG = {
    "host": "0.0.0.0",
    "port": 5000,
    "database": "malicious_isos.db",
    "upload_folder": "uploads"
}

# ================= INITIAL SETUP =================
def setup_environment():
    """Create necessary directories and database"""
    os.makedirs(CONFIG['upload_folder'], exist_ok=True)
    
    # Initialize database
    conn = sqlite3.connect(CONFIG['database'])
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS malicious_files
                 (hash TEXT PRIMARY KEY,
                  filename TEXT,
                  reason TEXT,
                  date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()
    
    print("✅ Environment setup complete")

# ================= CORE FUNCTIONS =================
def calculate_hash(file_path):
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_file_hash(file_hash):
    """Check if hash is in malicious database"""
    conn = sqlite3.connect(CONFIG['database'])
    c = conn.cursor()
    c.execute("SELECT reason FROM malicious_files WHERE hash=?", (file_hash,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

# ================= FLASK WEB SERVER =================
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = CONFIG['upload_folder']

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>ISO File Scanner</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 0 auto; padding: 20px; }
        .tab { overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1; }
        .tab button { background-color: inherit; float: left; border: none; outline: none;
                     cursor: pointer; padding: 14px 16px; transition: 0.3s; }
        .tab button:hover { background-color: #ddd; }
        .tab button.active { background-color: #ccc; }
        .tabcontent { display: none; padding: 6px 12px; border: 1px solid #ccc; border-top: none; }
        .safe { color: green; font-weight: bold; }
        .malicious { color: red; font-weight: bold; }
        .warning { color: orange; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .container { background: #f9f9f9; padding: 20px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>🔒 ISO File Security Scanner</h1>
    
    <div class="tab">
        <button class="tablinks" onclick="openTab(event, 'Check')" id="defaultTab">Check File</button>
        <button class="tablinks" onclick="openTab(event, 'Report')">Report File</button>
        <button class="tablinks" onclick="openTab(event, 'Database')">Malicious Database</button>
    </div>
    
    <div id="Check" class="tabcontent">
        <div class="container">
            <h2>📁 Check ISO File Safety</h2>
            <p>Upload an ISO file to check if it's in the malicious database:</p>
            <input type="file" id="checkFile" accept=".iso">
            <button onclick="checkFile()">Analyze File</button>
            <div id="checkResult" style="margin-top: 20px;"></div>
        </div>
    </div>
    
    <div id="Report" class="tabcontent">
        <div class="container">
            <h2>⚠️ Report Malicious ISO</h2>
            <p>Submit a malicious ISO file to add to the database:</p>
            <input type="file" id="reportFile" accept=".iso"><br><br>
            <input type="text" id="reason" placeholder="Why is this malicious? (e.g., 'contains virus')" size="50"><br><br>
            <button onclick="reportFile()">Submit Report</button>
            <div id="reportResult" style="margin-top: 20px;"></div>
        </div>
    </div>
    
    <div id="Database" class="tabcontent">
        <div class="container">
            <h2>📋 Known Malicious Files</h2>
            <div id="maliciousList">Loading...</div>
            <button onclick="loadDatabase()">Refresh List</button>
        </div>
    </div>
    
    <script>
    function openTab(evt, tabName) {
        var i, tabcontent, tablinks;
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }
        tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].className = tablinks[i].className.replace(" active", "");
        }
        document.getElementById(tabName).style.display = "block";
        evt.currentTarget.className += " active";
    }
    
    async function checkFile() {
        const file = document.getElementById('checkFile').files[0];
        if (!file) {
            alert('Please select a file first');
            return;
        }
        
        if (!file.name.toLowerCase().endsWith('.iso')) {
            alert('Please select an ISO file (.iso extension)');
            return;
        }
        
        const formData = new FormData();
        formData.append('file', file);
        
        document.getElementById('checkResult').innerHTML = '<div class="warning">Scanning file... Please wait.</div>';
        
        try {
            const response = await fetch('/api/check-file', {method: 'POST', body: formData});
            const result = await response.json();
            
            if (result.status === 'malicious') {
                document.getElementById('checkResult').innerHTML = 
                    `<div class="malicious">
                        <h3>❌ MALICIOUS ISO DETECTED!</h3>
                        <p><strong>File:</strong> ${file.name}</p>
                        <p><strong>Reason:</strong> ${result.reason}</p>
                        <p><strong>SHA256 Hash:</strong> ${result.hash}</p>
                        <p><strong>Action:</strong> Delete this file immediately!</p>
                    </div>`;
            } else {
                document.getElementById('checkResult').innerHTML = 
                    `<div class="safe">
                        <h3>✅ ISO FILE APPEARS SAFE</h3>
                        <p><strong>File:</strong> ${file.name}</p>
                        <p><strong>SHA256 Hash:</strong> ${result.hash}</p>
                        <p><strong>Status:</strong> Not found in malicious database</p>
                        <p><em>Note: Always scan files with antivirus software before use.</em></p>
                    </div>`;
            }
        } catch (error) {
            document.getElementById('checkResult').innerHTML = 
                `<div class="warning">Error: ${error.message}</div>`;
        }
    }
    
    async function reportFile() {
        const file = document.getElementById('reportFile').files[0];
        const reason = document.getElementById('reason').value;
        
        if (!file) {
            alert('Please select a file first');
            return;
        }
        
        if (!reason) {
            alert('Please provide a reason why this file is malicious');
            return;
        }
        
        const formData = new FormData();
        formData.append('file', file);
        formData.append('reason', reason);
        
        document.getElementById('reportResult').innerHTML = '<div class="warning">Submitting report...</div>';
        
        try {
            const response = await fetch('/api/report-file', {method: 'POST', body: formData});
            const result = await response.json();
            
            if (result.status === 'reported') {
                document.getElementById('reportResult').innerHTML = 
                    `<div class="safe">
                        <h3>✅ File Reported Successfully</h3>
                        <p><strong>File:</strong> ${file.name}</p>
                        <p><strong>SHA256 Hash:</strong> ${result.hash}</p>
                        <p><strong>Reason:</strong> ${reason}</p>
                        <p>This hash has been added to the malicious database.</p>
                    </div>`;
            } else {
                document.getElementById('reportResult').innerHTML = 
                    `<div class="warning">Error: ${result.error || 'Unknown error'}</div>`;
            }
        } catch (error) {
            document.getElementById('reportResult').innerHTML = 
                `<div class="warning">Error: ${error.message}</div>`;
        }
    }
    
    async function loadDatabase() {
        const response = await fetch('/api/list');
        const data = await response.json();
        
        if (data.files && data.files.length > 0) {
            let html = '<table>';
            html += '<tr><th>Hash (first 32 chars)</th><th>Reason</th><th>Date Added</th></tr>';
            data.files.forEach(f => {
                html += `<tr>
                    <td><code>${f.hash.substring(0, 32)}...</code></td>
                    <td>${f.reason}</td>
                    <td>${f.date_added ? f.date_added.split(' ')[0] : 'N/A'}</td>
                </tr>`;
            });
            html += '</table>';
            html += `<p>Total: ${data.files.length} malicious files in database</p>`;
            document.getElementById('maliciousList').innerHTML = html;
        } else {
            document.getElementById('maliciousList').innerHTML = 
                '<div class="safe">No malicious files in database yet.</div>';
        }
    }
    
    // Initialize
    document.getElementById("defaultTab").click();
    loadDatabase();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/check-file', methods=['POST'])
def api_check_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Verify it's an ISO file
    if not file.filename.lower().endswith('.iso'):
        return jsonify({"error": "File must have .iso extension"}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file.save(filepath)
        file_hash = calculate_hash(filepath)
        reason = check_file_hash(file_hash)
        
        # Clean up uploaded file
        os.remove(filepath)
        
        if reason:
            return jsonify({
                "status": "malicious", 
                "reason": reason, 
                "hash": file_hash,
                "filename": filename
            })
        return jsonify({
            "status": "clean", 
            "hash": file_hash,
            "filename": filename
        })
        
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({"error": str(e)}), 500

@app.route('/api/report-file', methods=['POST'])
def api_report_file():
    if 'file' not in request.files or 'reason' not in request.form:
        return jsonify({"error": "Missing file or reason"}), 400
    
    file = request.files['file']
    reason = request.form['reason']
    
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if not reason.strip():
        return jsonify({"error": "Reason cannot be empty"}), 400
    
    # Verify it's an ISO file
    if not file.filename.lower().endswith('.iso'):
        return jsonify({"error": "File must have .iso extension"}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file.save(filepath)
        file_hash = calculate_hash(filepath)
        
        # Add to database
        conn = sqlite3.connect(CONFIG['database'])
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO malicious_files (hash, filename, reason) VALUES (?, ?, ?)",
                  (file_hash, filename, reason))
        conn.commit()
        conn.close()
        
        os.remove(filepath)
        return jsonify({
            "status": "reported", 
            "hash": file_hash,
            "filename": filename
        })
        
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({"error": str(e)}), 500

@app.route('/api/list')
def api_list():
    try:
        conn = sqlite3.connect(CONFIG['database'])
        c = conn.cursor()
        c.execute("SELECT hash, reason, date_added FROM malicious_files ORDER BY date_added DESC")
        files = [{"hash": row[0], "reason": row[1], "date_added": row[2]} for row in c.fetchall()]
        conn.close()
        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/check-hash/<file_hash>')
def api_check_hash(file_hash):
    """Check a hash directly without uploading file"""
    if len(file_hash) != 64:
        return jsonify({"error": "Invalid SHA256 hash (must be 64 characters)"}), 400
    
    reason = check_file_hash(file_hash)
    if reason:
        return jsonify({"status": "malicious", "reason": reason, "hash": file_hash})
    return jsonify({"status": "clean", "hash": file_hash})

# ================= COMMAND LINE INTERFACE =================
def command_line_interface():
    """Simple command line interface"""
    print("\nCommands:")
    print("  check <hash>     - Check a SHA256 hash")
    print("  add <hash> <reason> - Add malicious hash")
    print("  list             - Show all malicious files")
    print("  web              - Open web interface")
    print("  exit             - Exit")
    
    while True:
        try:
            cmd = input("\n> ").strip().split()
            if not cmd:
                continue
                
            if cmd[0] == "check" and len(cmd) >= 2:
                file_hash = cmd[1]
                if len(file_hash) != 64:
                    print("❌ Invalid SHA256 hash (must be 64 characters)")
                    continue
                    
                reason = check_file_hash(file_hash)
                if reason:
                    print(f"❌ MALICIOUS: {reason}")
                else:
                    print("✅ Clean - Not in database")
                    
            elif cmd[0] == "add" and len(cmd) >= 3:
                file_hash = cmd[1]
                reason = " ".join(cmd[2:])
                
                if len(file_hash) != 64:
                    print("❌ Invalid SHA256 hash (must be 64 characters)")
                    continue
                    
                conn = sqlite3.connect(CONFIG['database'])
                c = conn.cursor()
                c.execute("INSERT OR REPLACE INTO malicious_files (hash, reason) VALUES (?, ?)",
                         (file_hash, reason))
                conn.commit()
                conn.close()
                print(f"✅ Added hash: {file_hash[:16]}...")
                
            elif cmd[0] == "list":
                conn = sqlite3.connect(CONFIG['database'])
                c = conn.cursor()
                c.execute("SELECT hash, reason FROM malicious_files")
                results = c.fetchall()
                conn.close()
                
                if results:
                    print(f"\n📋 Found {len(results)} malicious files:")
                    for i, (h, r) in enumerate(results, 1):
                        print(f"{i:2}. {h[:16]}... - {r}")
                else:
                    print("📋 Database is empty")
                    
            elif cmd[0] == "web":
                print(f"🌐 Web interface: http://{CONFIG['host']}:{CONFIG['port']}")
                
            elif cmd[0] == "exit":
                print("👋 Goodbye!")
                os._exit(0)
                
            else:
                print("❌ Unknown command. Type 'help' for commands.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            os._exit(0)
        except Exception as e:
            print(f"❌ Error: {e}")

# ================= MAIN EXECUTION =================
def main():
    """Main entry point"""
    print("=" * 50)
    print("🔒 ISO File Security Scanner")
    print("=" * 50)
    
    # Setup
    setup_environment()
    
    # Start CLI in background thread
    cli_thread = threading.Thread(target=command_line_interface, daemon=True)
    cli_thread.start()
    
    # Start Flask server
    print(f"🌐 Web Interface: http://{CONFIG['host']}:{CONFIG['port']}")
    print("💻 Command Line: Type commands below")
    print("📌 Press Ctrl+C to stop")
    print("=" * 50)
    
    try:
        app.run(host=CONFIG['host'], port=CONFIG['port'], debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n👋 Shutdown complete")
        sys.exit(0)

if __name__ == "__main__":
    # Check dependencies
    try:
        from flask import Flask
        from werkzeug.utils import secure_filename
    except ImportError:
        print("❌ Missing dependencies. Installing Flask...")
        try:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "flask", "werkzeug"])
            print("✅ Dependencies installed. Please restart the program.")
        except:
            print("❌ Failed to install dependencies. Please install manually:")
            print("   pip install flask werkzeug")
        sys.exit(1)
    
    # Run main program
    main()