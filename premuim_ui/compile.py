import PyInstaller.__main__
import os
import sys

def compile_executable():
    """Compile the educational simulation to executable"""
    
    print("🔒 EDUCATIONAL CYBERSECURITY SIMULATION COMPILER")
    print("This will create a safe demonstration executable.")
    print("No harmful code will be included.\n")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    main_script = os.path.join(current_dir, "main.py")
    
    if not os.path.exists(main_script):
        print("❌ Error: main.py not found!")
        return
    
    # PyInstaller arguments for safe educational executable
    args = [
        main_script,
        '--onefile',           # Single executable
        '--windowed',          # No console window
        '--name=YouTubePremiumActivator',  # Descriptive name
        '--clean',             # Clean build
        '--noconfirm',         # Don't ask for confirmation
        '--add-data="requirements.txt;."',  # Include requirements
        '--hidden-import=PIL', # Include PIL
        '--hidden-import=PIL._tkinter_finder',
    ]
    
    print("📦 Compiling educational simulation...")
    try:
        PyInstaller.__main__.run(args)
        print("✅ Compilation successful!")
        print(f"📍 Executable location: {current_dir}/dist/YouTubePremiumActivator.exe")
        print("\n🔒 SAFETY REMINDER:")
        print("This is for EDUCATIONAL purposes only!")
        print("Use the provided remove_startup.py to clean up if needed.")
        
    except Exception as e:
        print(f"❌ Compilation failed: {e}")

if __name__ == "__main__":
    compile_executable()