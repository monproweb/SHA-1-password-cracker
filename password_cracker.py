import hashlib

def get_password_hash(password, salt=None, prep=True):
    hash_mod = hashlib.sha1()
    if salt:
        if prep:
            password = (salt + password)
        else:
            password = (password + salt)

    hash_mod.update(password.encode('utf-8'))
    return hash_mod.hexdigest()

def crack_sha1_hash(hash, use_salts=False):
    salts = list()
    passwords = list()
    with open('known-salts.txt', 'r') as salts_fd:
        # Read and print the entire file line by line
        salts = salts_fd.readlines()
        
    with open('top-10000-passwords.txt', 'r') as passwrd_fd:
        # Read and print the entire file line by line
        passwords = passwrd_fd.readlines()

    if not use_salts:
        for password in passwords:
            p_hash = get_password_hash(password.rstrip())
            if p_hash == hash:
                return password.rstrip()
        
        return "PASSWORD NOT IN DATABASE"
    else:
        for password in passwords:
            for salt in salts:
                p_hash_prep = get_password_hash(password.rstrip(), salt.rstrip())
                p_hash_app = get_password_hash(password.rstrip(), salt.rstrip(), False)
                if p_hash_prep == hash or p_hash_app == hash:
                    return password.rstrip()
    
    return "PASSWORD NOT IN DATABASE"