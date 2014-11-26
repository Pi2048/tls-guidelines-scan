import sys
import xml.etree.ElementTree as ET
import colorama
from subprocess import call

host = sys.argv[1]
port = sys.argv[2]
args = []

if len(sys.argv) > 3:
    for arg in sys.argv[3:]:
        args.append(arg)

command_list = ['./sslyze.py', '--sslv2', '--sslv3', '--tlsv1', '--tlsv1_1', '--tlsv1_2',
                 '--reneg', '--certinfo=basic', '--hide_rejected_ciphers', 
                 '--compression', '--xml_out=outfile.xml']
command_list.extend(args)
command_list.append('{0}:{1}'.format(host, port))

call(command_list)
                    
versions = ['sslv2', 'sslv3', 'tlsv1', 'tlsv1_1', 'tlsv1_2']

tree = ET.parse('outfile.xml')
root = tree.getroot()

def check_versions():
    '''
    Guideline B1-1: All supported TLS versions are Sufficient or Good.

    Returns True iff the server only supports Sufficient or Good TLS versions.

    none -> bool
    '''
    insufficient_versions = ['sslv2', 'sslv3']
    sufficient_versions = ['tlsv1', 'tlsv1_1']
    good_versions = ['tlsv1_2']

    for version in insufficient_versions:
        version_node = root.findall('./results/target/{0}'.format(version))[0]
        accepted_cipher_suites = version_node.findall('./acceptedCipherSuites/*')
        if len(accepted_cipher_suites) > 0:
            return False
    
    return True

def check_certificate_verification_algorithms():
    '''
    Guideline B2-1: All supported cipher suites contain a Sufficient or Good algorithm for 
    certificate verification.

    Returns True iff the server only supports cipher suites with Sufficient or Good
    algorithms for certificate verification.

    The method decides that the following conditions should lead to False:
    - The cipher suite name starts with 'EXP' or 'PSK'
    - The cipher suite name contains 'ADH' or 'AECDH'

    none -> bool
    '''
    for version in versions:
        version_node = root.findall('./results/target/{0}'.format(version))[0]
        accepted_cipher_suites = version_node.findall('acceptedCipherSuites/cipherSuite')
        for cipher_suite in accepted_cipher_suites:
            suite_name = cipher_suite.get('name')
            if suite_name.startswith('EXP'):
                return False
            if suite_name.startswith('PSK'):
                return False
            if 'AECDH' in suite_name:
                return False
            if 'ADH' in suite_name:
                return False
    return True

def check_key_exchange_algorithms():
    '''
    Guideline B2-2: All supported cipher suites contain a Sufficient or Good algorithm for 
    key exchange.

    Returns True iff the server only supports cipher suites with Sufficient or Good
    algorithms for key exchange.
    
    As OpenSSL does not support SRP or KRB5 cipher suites, we can only check for PSK cipher
    suites.

    none -> bool
    '''
    for version in versions:
        version_node = root.findall('./results/target/{0}'.format(version))[0]
        accepted_cipher_suites = version_node.findall('acceptedCipherSuites/cipherSuite')
        for cipher_suite in accepted_cipher_suites:
            suite_name = cipher_suite.get('name')
            if suite_name.startswith('PSK'):
                return False
    return True
    
def check_bulk_encryption_algorithms():
    '''
    Guideline B2-3: All supported cipher suites contain a Sufficient or Good algorithm for 
    bulk encryption.

    Returns True iff the server only supports cipher suites with Sufficient or Good
    algorithms for bulk encryption.

    none -> bool
    '''
    good_algorithms = ['AES128-GCM', 'AES256-GCM'] # OpenSSL does not support CAMELLIA-GCM
    sufficient_algorithms = ['DES-CBC3', 'AES128-SHA', 'AES256-SHA', 'AES128-CBC', 'AES256-CBC', 'CAMELLIA128', 'CAMELLIA256', 'ARIA', 'SEED']
    acceptable_algorithms = good_algorithms + sufficient_algorithms

    for version in versions:
        version_node = root.findall('./results/target/{0}'.format(version))[0]
        accepted_cipher_suites = version_node.findall('acceptedCipherSuites/cipherSuite')
        for cipher_suite in accepted_cipher_suites:
            suite_name = cipher_suite.get('name')
            cipher_is_good = False
            for algorithm in acceptable_algorithms:
                if algorithm in suite_name:
                    cipher_is_good = True
            if not cipher_is_good:
                return False
    return True
            
def check_hashing_algorithms():
    '''
    Guideline B2-4: All supported cipher suites contain a Sufficient or Good algorithm for 
    hashing.

    Returns True iff the server only supports cipher suites with Sufficient or Good
    algorithms for hashing.

    none -> bool
    '''
    for version in versions:
        version_node = root.findall('./results/target/{0}'.format(version))[0]
        accepted_cipher_suites = version_node.findall('acceptedCipherSuites/cipherSuite')
        for cipher_suite in accepted_cipher_suites:
            suite_name = cipher_suite.get('name')
            if not 'SHA' in suite_name:
                return False
    return True

def check_certificate_existence():
    '''
    Guideline B3-1: The server offers a certificate for authentication.

    Returns True iff the server has authenticated itself by offering a certificate.
    
    none -> bool
    '''
    certificates = root.findall('./results/target/certinfo/certificateChain/certificate[@position="leaf"]')
    if len(certificates) > 0:
        return True
    return False

def check_certificate_fingerprint():
    '''
    Guideline B3-2: The signed fingerprint of the certificate is made with a Good algorithm for hashing.

    Returns True iff the certificate was signed using a Good certificate for hashing.

    none -> bool
    '''
    signature_algorithms = root.findall('./results/target/certinfo/certificateChain/certificate[@position="leaf"]/signatureAlgorithm')
    for algorithm in signature_algorithms:
        if (not 'sha256With' in algorithm.text and 
            not 'sha384With' in algorithm.text and 
            not 'sha512With' in algorithm.text):
            return False
    return True

def check_certificate_rsa_keylength():
    '''
    Guideline B3-3: If the server offers a certificate with an RSA key, the length of this key is at least Sufficient.

    Returns True iff all RSA keys in all offered certificates are of Sufficient length.

    none -> bool
    '''
    certificates = root.findall('./results/target/certinfo/certificateChain/certificate[@position="leaf"]')
    for certificate in certificates:
        algorithm = certificate.findall('./subjectPublicKeyInfo/publicKeyAlgorithm')[0].text
        if algorithm == 'rsaEncryption':
            key_size = certificate.findall('./subjectPublicKeyInfo/publicKeySize')[0].text
            if key_size.split(' ')[0].isdigit() and int(key_size.split(' ')[0]) < 2048:
                return False
    return True
    
def check_certificate_dsa_keylength():
    '''
    Guideline B3-4: If the server offers a certificate with a DSS key, the length of the public key is
    at least Sufficient and the length of the private key is at least Sufficient.

    Returns True iff all DSS keys in all offered certificates have a public part and a private part 
    of Sufficient length.

    none -> bool
    '''
    certificates = root.findall('./results/target/certinfo/certificateChain/certificate[@position="leaf"]')
    for certificate in certificates:
        algorithm = certificate.findall('./subjectPublicKeyInfo/publicKeyAlgorithm')[0].text
        if algorithm == 'dsaEncryption':
            q_key = certificate.findall('./subjectPublicKeyInfo/publicKeyAlgorithm/Q')[0].text
            p_key = certificate.findall('./subjectPublicKeyInfo/publicKeyAlgorithm/P')[0].text
            if len(q_key) < (224 / 8) * 3 - 1: # Length of hex-encoded value of Q
                return False
            if len(p_key) < (2048 / 8) * 3 -1: # Length of hex-encoded value of P
                return False
    return True

def check_certificate_ecdsa_keylength():
    '''
    Guideline B3-5: If the server offers a certificate with an ECDSA key, the length of this key is at least Sufficient.

    Returns True iff all ECDSA keys in all offered certificates are of Sufficient length.

    none -> bool
    '''
    certificates = root.findall('./results/target/certinfo/certificateChain/certificate[@position="leaf"]')
    for certificate in certificates:
        algorithm = certificate.findall('./subjectPublicKeyInfo/publicKeyAlgorithm')[0].text
        if algorithm == 'id-ecPublicKey':
            key_size = certificate.findall('./subjectPublicKeyInfo/publicKeySize')[0].text
            if key_size.split(' ')[0].isdigit() and int(key_size.split(' ')[0]) < 256:
                return False
    return True

def check_certificate_chain():
    '''
    Guideline B3-6: If the server certificate is not directly signed by the root CA, the server offers intermediate CA's
    between the root CA and the server certificate for authentication.

    Returns True iff the certificate chain offered can be validated to at least one trusted CA store.

    none -> bool
    '''
    if len(root.findall('./results/target/certinfo/certificateValidation/pathValidation[@validationResult="ok"]')) > 0:
        return True
    return False

def check_dh_public_parameters():
    '''
    Guideline B4-1: If DH or DHE are used for key exchange, the length of the used public parameters is at least Sufficient.
    
    Returns True iff the DH public parameters used for key exchange are of Sufficient length.

    none -> bool
    '''
    dh_key_exchanges = root.findall('./results/target/*/acceptedCipherSuites/cipherSuite/keyExchange[@Type="DH"]')
    for kex in dh_key_exchanges:
        if int(kex.get('GroupSize')) < 2048:
            return False
    return True

def check_dh_secret_parameters():
    '''
    Guideline B4-2: If DH or DHE are used for key exchange, the length of the used secret parameters is at least Sufficient.
    
    Always returns True. There is no way to verify the length of the secret DH parameters externally.

    none -> bool
    '''
    return True

def check_ecdh_parameters():
    '''
    Guideline B4-3: If ECDH or ECDHE are used for key exchange, the length of the used parameters is at least Sufficient.

    Returns True iff the DH public parameters used for key exchange are of Sufficient length.

    none -> bool
    '''
    ecdh_key_exchanges = root.findall('./results/target/*/acceptedCipherSuites/cipherSuite/keyExchange[@Type="ECDH"]')
    for kex in ecdh_key_exchanges:
        if int(kex.get('GroupSize')) < 256:
            return False
    return True
    
def check_elliptic_curves():
    '''
    Guideline B5-1: All used elliptic curves are Sufficient or Good.

    Returns True iff only Sufficient or Good curves are used as a domain for ECDSA public keys or ECDH(E) key exchange.

    none -> bool
    '''
    sufficient_curves = [ # The names of Sufficient or Good curves
        'secp224r1',
        'secp256r1',
        'secp384r1',
        'secp521r1',
        'brainpoolP256r1',
        'brainpoolP384r1',
        'brainpoolP512r1'
    ]
    sufficient_b = [ # The B parameters of Sufficient or Good curves
        '0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4', #secp224r1, sufficient
        '0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b', #secp256r1
        '0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef', #secp384r1
        '0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00', #secp521r1
        '0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6', #brainpoolP256r1
        '0x4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11', #brainpoolP384r1
        '0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723' #brainpoolP512r1
    ]

    # Check curves used as ECDSA domain
    certificates = root.findall('./results/target/certinfo/certificateChain/certificate[@position="leaf"]')
    for certificate in certificates:
        algorithm = certificate.findall('./subjectPublicKeyInfo/publicKeyAlgorithm')[0].text
        if algorithm == 'id-ecPublicKey':
            curve = certificate.findall('./subjectPublicKeyInfo/publicKeyAlgorithm/ASN1OID')[0].text
            if not curve in sufficient_curves:
                return False

    # Check curves used as ECDH(E) domain
    ecdh_key_exchanges = root.findall('./results/target/*/acceptedCipherSuites/cipherSuite/keyExchange[@Type="ECDH"]')
    for kex in ecdh_key_exchanges:
        if kex.get('B').lower() not in [b.lower() for b in sufficient_b]:
            return False
    return True
    
def check_compression():
    '''
    Guideline B6-1: The settings for compression are Sufficient or Good.

    Returns True iff the compression settings are Sufficient or Good (i.e. TLS compression is off).

    none -> bool
    '''
    if len(root.findall('./results/target/compression/compressionMethod[@isSupported="True"][@type="DEFLATE"]')) > 0:
        return False
    return True

def check_renegotiation():
    '''
    Guideline B6-2: The settings for renegotiation are Sufficient or Good.

    Returns True iff both insecure renegotiation and client-initiated renegotiation are disabled.

    none -> bool
    ''' 
    renegotiation_settings = root.findall('./results/target/reneg/sessionRenegotiation')
    if len(renegotiation_settings) != 1:
        return False
    if renegotiation_settings[0].get('canBeClientInitiated') == "True":
        return False
    if renegotiation_settings[0].get('isSecure') == "False":
        return False
    return True

def do_check(guideline, checker):
    '''
    Executes checker to check whether guideline holds. Prints the result. Guideline is the
    identifier of the guideline being checked (e.g. 'B3-4 DSS certificates'). Checker is 
    a function pointer to the appropratie checking function. Checker should require no 
    arguments and should return a bool indicating whether the guideline was followed 
    correctly (True is pass).

    (str, method) -> none
    '''
    if checker():
        finding = colorama.Fore.GREEN + 'PASS' + colorama.Fore.RESET
    else:
        finding = colorama.Fore.RED + 'FAIL' + colorama.Fore.RESET

    print "{0:.<50} {1}".format(guideline + " ", finding)

colorama.init()

print "="*55
print "*{0: ^53}*".format("Report for {0}:{1}".format(host, port))
print "="*55
print ""
do_check("B1-1 Versions", check_versions)
do_check("B2-1 Cipher suites - certificate verification", check_certificate_verification_algorithms)
do_check("B2-2 Cipher suites - key exchange", check_key_exchange_algorithms)
do_check("B2-3 Cipher suites - bulk encryption", check_bulk_encryption_algorithms)
do_check("B2-4 Cipher suites - hashing algorithms", check_hashing_algorithms)
do_check("B3-1 Certificates - existence", check_certificate_existence)
do_check("B3-2 Certificates - fingerprint", check_certificate_fingerprint)
do_check("B3-3 Certificates - RSA key length", check_certificate_rsa_keylength)
do_check("B3-4 Certificates - DSS key length", check_certificate_dsa_keylength)
do_check("B3-5 Certificates - ECDSA key length", check_certificate_ecdsa_keylength)
do_check("B3-6 Certificates - chain", check_certificate_chain)
do_check("B4-1 Diffie-Hellman - DH(E) public parameters", check_dh_public_parameters)
do_check("B4-2 Diffie-Hellman - DH(E) secret parameters", check_dh_secret_parameters)
do_check("B4-3 Diffie-Hellman - ECDH(E) parameters", check_ecdh_parameters)
do_check("B5-1 Elliptic curves", check_elliptic_curves)
do_check("B6-1 Other - compression", check_compression)
do_check("B6-2 Other - renegotiation", check_renegotiation)

