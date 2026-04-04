import secrets

# RFC 3526, Group 14
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2
Q = (P - 1) // 2

# returns a tuple of (private_key, public_key)
def generate_keypair() -> tuple[int, int]:
    x = secrets.randbelow(Q - 1) + 1
    Y = pow(G, x, P)
    return x, Y

# returns a tuple of (commitment, public_commitment)
def generate_commitment() -> tuple[int, int]:
    r = secrets.randbelow(Q - 1) + 1
    T = pow(G, r, P)
    return r, T

# returns a random int belonging to the cyclic subgroup of prime order Q (challenge)
def generate_challenge() -> int:
    return secrets.randbelow(Q - 1) + 1

# returns the response of challenge
def generate_response(r: int, c: int, x: int) -> int:
    return (r - c * x) % Q

# checks if the proof is valid or not
def verify(Y: int, T: int, c: int, s: int) -> bool:
    lhs = (pow(G, s, P) * pow(Y, c, P)) % P
    return lhs == T

# calculates others_public_key**my_private_key
def dh_agree(my_private: int, their_public: int) -> int:
    return pow(their_public, my_private, P)

# generates a private random (r, R)
def ephemeral_keypair() -> tuple[int, int]:
    r = secrets.randbelow(Q - 1) + 1
    R = pow(G, r, P)
    return r, R