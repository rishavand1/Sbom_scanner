# Sbom_scanner

# STEP 1
sudo apt update< br /> 
sudo apt install python3 python3-pip -y

# STEP 2
git clone https://github.com/rishavand1/Sbom_scanner.git< br /> 
cd sbom-scanner

# STEP 3
pip3 install -r requirements.txt

# STEP 4
python3 sbom_scanner.py /path/to/sbom_file.json

# Example Usage
python3 sbom_scanner.py dependencies.json

# Result
cat sbom_scanner.log
