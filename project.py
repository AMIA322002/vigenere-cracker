import re
from collections import Counter
import string
from itertools import cycle

# English letter frequencies (from highest to lowest)
ENGLISH_FREQ = [
    'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'c', 'u', 'm', 'w', 'f', 'g', 'y', 'p', 'b', 'v', 'k', 'j', 'x', 'q', 'z'
]

def clean_text(ciphertext):
    """Remove punctuation and numbers, keep only letters and convert to lowercase"""
    return re.sub(r'[^a-zA-Z]', '', ciphertext).lower()

def kasiski_examination(ciphertext, max_key_length=15):
    """Estimate key length using Kasiski examination"""
    # Find repeated sequences of 3+ characters and their distances
    sequences = {}
    for i in range(len(ciphertext) - 2):
        seq = ciphertext[i:i+3]
        if seq in sequences:
            sequences[seq].append(i)
        else:
            sequences[seq] = [i]
    
    # Filter sequences that appear at least twice
    repeated_seqs = {k: v for k, v in sequences.items() if len(v) > 1}
    
    # Calculate distances between repeated sequences
    distances = []
    for positions in repeated_seqs.values():
        for i in range(len(positions)):
            for j in range(i+1, len(positions)):
                distances.append(positions[j] - positions[i])
    
    # Find common factors of these distances
    def get_factors(n):
        return set([i for i in range(2, max_key_length+1) if n % i == 0])
    
    common_factors = Counter()
    for d in distances:
        factors = get_factors(d)
        for f in factors:
            common_factors[f] += 1
    
    # Return the most likely key lengths (top 3)
    return [k for k, v in common_factors.most_common(3)]

def get_cosets(ciphertext, key_length):
    """Split ciphertext into cosets for each key character"""
    return [ciphertext[i::key_length] for i in range(key_length)]

def frequency_analysis(coset):
    """Perform frequency analysis on a coset to find most likely shift"""
    counts = Counter(coset)
    total = len(coset)
    
    best_shift = 0
    best_score = -1
    
    # Try all possible shifts (0-25)
    for shift in range(26):
        score = 0
        for c in counts:
            # Calculate the expected letter after undoing the shift
            expected_char = chr(((ord(c) - ord('a') - shift) % 26) + ord('a'))
            # Score based on English frequency (higher is better)
            score += counts[c] * (26 - ENGLISH_FREQ.index(expected_char)) if expected_char in ENGLISH_FREQ else 0
        
        if score > best_score:
            best_score = score
            best_shift = shift
    
    return best_shift

def crack_vigenere(ciphertext):
    """Main function to crack Vigenère cipher"""
    # Clean the ciphertext (remove non-letters)
    cleaned = clean_text(ciphertext)
    
    # Step 1: Estimate key length using Kasiski examination
    possible_lengths = kasiski_examination(cleaned)
    print(f"Possible key lengths: {possible_lengths}")
    
    # Try each possible key length starting with the most likely
    for key_length in possible_lengths:
        print(f"\nTrying key length: {key_length}")
        
        # Step 2: Split into cosets
        cosets = get_cosets(cleaned, key_length)
        
        # Step 3: Perform frequency analysis on each coset
        key = []
        for i, coset in enumerate(cosets):
            shift = frequency_analysis(coset)
            key_char = chr(shift + ord('a'))
            key.append(key_char)
        
        key = ''.join(key)
        print(f"Potential key: {key}")
        
        # Step 4: Attempt decryption with this key
        decrypted = decrypt_vigenere(ciphertext, key)
        print(f"Decrypted text (first 100 chars): {decrypted[:100]}...")
        
        # Ask user if this looks correct
        response = input("Does this look correct? (y/n): ").lower()
        if response == 'y':
            return key, decrypted
    
    # If none of the automatic attempts worked, prompt for manual key length
    print("Automatic attempts unsuccessful. Trying manual key length...")
    for key_length in range(5, 16):
        if key_length not in possible_lengths:
            print(f"\nTrying key length: {key_length}")
            cosets = get_cosets(cleaned, key_length)
            key = []
            for i, coset in enumerate(cosets):
                shift = frequency_analysis(coset)
                key_char = chr(shift + ord('a'))
                key.append(key_char)
            
            key = ''.join(key)
            print(f"Potential key: {key}")
            decrypted = decrypt_vigenere(ciphertext, key)
            print(f"Decrypted text (first 100 chars): {decrypted[:100]}...")
            response = input("Does this look correct? (y/n): ").lower()
            if response == 'y':
                return key, decrypted
    
    return None, None

def decrypt_vigenere(ciphertext, key):
    """Decrypt ciphertext using a known key"""
    key = key.lower()
    key_cycle = cycle(key)
    decrypted = []
    key_index = 0
    
    for c in ciphertext:
        if c.lower() in string.ascii_lowercase:
            # Calculate shift
            key_char = next(key_cycle)
            shift = ord(key_char) - ord('a')
            
            # Decrypt the character
            if c.isupper():
                decrypted_char = chr(((ord(c.lower()) - ord('a') - shift) % 26) + ord('a')).upper()
            else:
                decrypted_char = chr(((ord(c) - ord('a') - shift) % 26) + ord('a'))
            
            decrypted.append(decrypted_char)
        else:
            # Keep non-alphabetic characters as-is
            decrypted.append(c)
    
    return ''.join(decrypted)

# Example usage with the provided ciphertext
ciphertext = """
Nul Vkqeopvy Pppjor jd e grahqn og prwefpvsnh lpjuhbgdid eirg. Pt wcet l wczwlg posx sz cvlaklqsevraie cucdxcgbtkyn. B asflhlrracpxcp jirres tw uaf ckzhfc fufld qx svmwnvauvsoo, fwcan mwvtjapy fbbudiufxcbu anzhbminf. Ahg ondccjgpop yf usi iepgkxam eirg ps fynf fwcan tjo Vjrihrye uaubci ie Ciionfci nnilg. Dhf Gmarueto tbmpy vz a 26z26 qrjo sz goe cvpilfyg dhgbe flgb evw kc a Dlimny ckzhfc acgo a urige ikhhl vy tip vij uuoles. Ely pppjor vdim n reagoso xi qltgbmjyi qupcj box es ofl fqb ebnl fratgb io ely csakxtfix. Cs ahg uezhslq ps uroseil goap dhf apuvutght, je mm elpgktfo xi zhter tip pyantj yf usi grzscqe. Epwjvae doior mhilnvod jy xbr 16ah eonufvs nud qxcf nshfpdgbee frvelamkbmp, xbr Ciionfci Wvwhgb cby rij ie dbolpr ofpni fastsof jraztbyeflziu dedsrcdbeu cuds em syeseeonc uahlacit, ely Xhskckj pbuzpncdipy, ehq ahg Prjphgnu tgct.
"""

# Crack the cipher
key, plaintext = crack_vigenere(ciphertext)

if key and plaintext:
    print("\nSuccess!")
    print(f"Key: {key}")
    print(f"Plaintext:\n{plaintext}")
else:
    print("Failed to crack the cipher automatically. Try adjusting parameters or examining manually.")