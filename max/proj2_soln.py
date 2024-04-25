import uva_rsa 
import secrets
import time
import random

########################################################### 
# Problem 1: 6-bit Prefix
# Recover the first 6 bits of the secret key
########################################################### 
def problem1(pub_e, pub_n, oracle):
    sk_6bit = 0x00
    #
    # Write your solution here.
    # Call oracle.run_6bits(...) with same or different inputs,
    # and then use the consumed time to recover the 6 bits.
    #

    #Implementation 1 -> theoretically gets answer 1/10 vs 1/100 times
    ct = uva_rsa.rsa_enc(pub_e, pub_n, 0xABCD0123)
    reps = 10000

    key_len = 2048
    bitstrings = [int('0'*2048,2),int('1' + '0'*2047,2),int('11' + '0'*2046,2),int('111' + '0'*2045,2),int('1111' + '0'*2044,2),int('11111' + '0'*2043,2),int('111111' + '0'*2041,2)]
    potential_sk_oracles = [uva_rsa.DecryptOracleA(bitstring,pub_n) for bitstring in bitstrings]
    potenital_sk_timings = []

    for potential_oracle in potential_sk_oracles:
        potential_timing = get_decrypt_timing(reps,potential_oracle,ct)
        potenital_sk_timings.append(potential_timing)

    print(potenital_sk_timings)
    reps = 10000
    actual_timing = get_decrypt_timing(reps,oracle,ct)
    print(actual_timing)

    closest_index,closest_value , = min(enumerate(potenital_sk_timings), key=lambda timing: abs(timing[1] - actual_timing))
    print(closest_index,closest_value)
    print(prefix(bitstrings[closest_index],6))
    return prefix(bitstrings[closest_index],6)

def get_decrypt_timing(reps,oracle,ct):
    start = time.process_time_ns()
    for _ in range(reps):
        oracle.run_6bits(ct)
    end = time.process_time_ns()
    return (end - start)/reps

def prefix(integer, bitlen):
    bits = format(integer, 'b')
    bits = bits.zfill(2048)[0:bitlen]
    return int(bits, 2)
  

########################################################### 
# Problem 2: 3-bit Prefix (continued)
# Recover the first 3 bits of the secret key
########################################################### 
def problem2(pub_e, pub_n, oracle):
    sk_3bit = 0x00
    #
    # Write your solution here.
    # Call oracle.run(...) with same or different inputs,
    # and then use the consumed time to recover the 3 bits.
    #
    ct = uva_rsa.rsa_enc(pub_e, pub_n, 0xABCD0123)
    reps = 50
    start = time.process_time_ns()
    for i in range(reps):
        oracle.run(ct)
    end = time.process_time_ns()
    print((end - start)/reps) ### print only for testing purpose, not needed in your submission  

    return sk_3bit

########################################################### 
# Problem 3: The whole 2048 bits
# Recover the (roughly) 2048 bits of the secret key
########################################################### 
def problem3(pub_e, pub_n, oracle):
    sk = 0x00
    #
    # Write your solution here.
    # Call oracle.run(...) with same or different inputs,
    # and then use the consumed time to recover the secret key.
    #
    ct = uva_rsa.rsa_enc(pub_e, pub_n, 0xABCD0123)
    reps = 50
    start = time.process_time_ns()
    for i in range(reps):
        oracle.run(ct)
    end = time.process_time_ns()
    print((end - start)/reps) ### print only for testing purpose, not needed in your submission  

    return sk

########################################################### 
# Some examples and test cases.
# You shall write your own tests, but you do not need to
# submit them (only the above three functions are graded).
########################################################### 
if __name__ == '__main__':
    # A sample key, 2048-bits
    key1 = {"e": 65537,
        "n": 26334846008439167556765994336545761339068098619101850421771908459419918602128141355234077943248935530058859245371916765929458717691408496374069803243864206525054456891054239459424634162712907872176687992073038190824711743119057398524481757063408686486317239808826593650469866307923539528308953119230902384306178943542441126686061578352279102334653866502920311536313397546287885026738627086034614799371467801646963827587890747711299932470791488642354928910842955461742067813873505900679667440625963269380243732319252322289624537679679000548719937080897079171234468074929759669376046003568677119493377927698383184444971,
        "d": 4150452954516788305322334373505934224092414147025341858259381425646659178605691706486212654370727684626846117494529293210823262969746501329504015330861438248564932422166878714870792714969678806278402238259157411843640134215067682273010431589510827287426792759999212883054785908980030403151122652491713875272966953950697706468122810899702465849201975767642644740088526762001961677935216877828845320587721250185528209814840248616253000685484141272453417580384407258920262649904440074465914446977660642607238586680208905768616792883391776390693711645020742189552372320510460581645319646313943217496379479242398240521369}
    # Random key generation, 2048-bits:
    # key = uva_rsa.rsa_gen()
    key = key1
    
    # Problem 1
    print("Problem 1:")
    oracle = uva_rsa.DecryptOracleA(key["d"], key["n"])
    print(uva_rsa.prefix(key["d"], 6))
    if problem1(key["e"], key["n"], oracle) == uva_rsa.prefix(key["d"], 6):
        print("Problem 1 correct")

    # Problem 2
    print("Problem 2:")
    oracle = uva_rsa.DecryptOracleB(key["d"], key["n"])
    if problem2(key["e"], key["n"], oracle) == uva_rsa.prefix(key["d"], 3):
        print("Problem 2 correct")

    # Problem 3
    print("Problem 3:")
    oracle = uva_rsa.DecryptOracleB(key["d"], key["n"])
    if problem3(key["e"], key["n"], oracle) == key["d"]:
        print("Problem 3 correct")
