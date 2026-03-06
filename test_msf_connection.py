import sys
sys.path.insert(0, 'backend')

from pymetasploit3.msfrpc import MsfRpcClient

print("Testing Metasploit connection...")
print("-" * 50)

try:
    # Try to connect
    print("Connecting to 127.0.0.1:55553...")
    print("Username: msf")
    print("Password: mypassword123")
    print("SSL: False")
    print()
    
    client = MsfRpcClient(
        'mypassword123',
        server='127.0.0.1',
        port=55553,
        ssl=False
    )
    
    # Test connection
    version = client.call('core.version')
    
    print("✅ CONNECTION SUCCESSFUL!")
    print(f"Metasploit version: {version['version']}")
    print(f"Ruby version: {version['ruby']}")
    print()
    
    # List some exploits
    print("Testing exploit search...")
    exploits = client.modules.exploits
    print(f"Found {len(exploits)} exploit modules")
    print()
    
    # Test a simple call
    print("Testing API call...")
    result = client.call('core.module_stats')
    print(f"Total modules: {result}")
    print()
    
    print("✅ ALL TESTS PASSED!")
    
except Exception as e:
    print(f"❌ CONNECTION FAILED!")
    print(f"Error: {str(e)}")
    print()
    print("Possible causes:")
    print("1. RPC server not running (check msf6 console)")
    print("2. Wrong password in script")
    print("3. Wrong port number")
    print("4. Firewall blocking connection")