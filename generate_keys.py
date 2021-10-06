from tinyec import registry
import secrets

def generate_key_pair(device_id):
    #Getting the 'brainpoolP256r1' curve from the registry
    curve = registry.get_curve('brainpoolP256r1')

    #Generating Alice's private
    privatekey = secrets.randbelow(curve.field.n)
    print("Alice's private key: ", privatekey)

    #Generate Alice's publickey from her private key and Generator point
    publickey = privatekey * curve.g
    print("Alice's public key: ", publickey)

    return (privatekey, publickey)

generate_key_pair(1)
