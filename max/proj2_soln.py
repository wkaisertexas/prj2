import time
import timeit
import uva_rsa
import secrets
import random
import numpy as np
import scipy.stats as stats

def get_decrypt_timing(reps,oracle,ct):
    start = time.perf_counter_ns()
    for _ in range(reps):
        oracle.run_6bits(ct)
    end = time.perf_counter_ns()
    return (end - start)/reps

def prefix(integer, bitlen):
    bits = format(integer, 'b')
    bits = bits.zfill(2048)[0:bitlen]
    return int(bits, 2)

def mod_exp(base, exponent, modulus):
    bits = format(exponent, 'b')
    y = 1
    for b in bits:
        y = (y * y) % modulus
        if '1' == b:
            y = (y * base) % modulus
    return y

def get_exp_timing(base,exponent,modulus,reps):
    start = time.perf_counter_ns()
    for i in range(reps):
        mod_exp(base,exponent,modulus)
        ##print(i)
    end = time.perf_counter_ns()
    return (end-start)/(reps)

def get_oracle_timing(oracle,ct,reps):
    start = time.perf_counter_ns()
    for i in range(reps):
        oracle.run(ct)
        ##print(i)
    end = time.perf_counter_ns()
    return (end-start)/(reps)

def get_exp_timing_timeit(base,exponent,modulus,reps):
    setup_code = """from __main__ import mod_exp"""
    statement = """mod_exp(base,exponent,modulus)"""
    execution_time = timeit.timeit(stmt=statement, setup=setup_code,globals = locals(),number = 1000)
    return execution_time

def get_oracle_timing_timeit(oracle,ct,reps):
    setup_code = """from uva_rsa import DecryptOracleB"""
    statement = """oracle.run(ct)"""
    execution_time = timeit.timeit(stmt=statement, setup=setup_code,globals=locals(), number = 1000)
    return execution_time

def get_exp_timing_timeit_repeat(base, exponent, modulus, reps):
    setup_code = """from __main__ import mod_exp"""
    statement = """mod_exp(base, exponent, modulus)"""
    execution_times = timeit.repeat(stmt=statement, setup=setup_code, repeat=10, number=10,globals=locals())
    return min(execution_times)

def get_oracle_timing_timeit_repeat(oracle, ct, reps):
    setup_code = """from uva_rsa import DecryptOracleB"""
    statement = """oracle.run(ct)"""
    execution_times = timeit.repeat(stmt=statement, setup=setup_code, repeat=10, number=10,globals=locals())
    return min(execution_times)

def time_samples_method_one(samples,sample_keys,pred_reps,actual_reps,timings,oracle,ct,key1):
    actual_timing = []
    for _ in range(samples):
        for index,key in enumerate(sample_keys): #gets samples amount of timing data
            timings[index].append(get_exp_timing(ct,key,key1["n"],pred_reps))        
        actual_timing.append(get_oracle_timing(oracle,ct,actual_reps))

    for index,_ in enumerate(timings):
        timings[index] = np.mean([x for x in timings[index] if np.percentile(timings[index],15) < x < np.percentile(timings[index],85)]) #finds the mean of the data with outlier timings excluded
    actual_timing = np.mean([x for x in actual_timing if np.percentile(actual_timing,15) < x < np.percentile(actual_timing,85)])
    return actual_timing
    
def time_samples_method_two(sample_keys,ct,key1,pred_reps,oracle,actual_reps,timings,actual_timing):
    for index,key in enumerate(sample_keys): #gets samples amount of timing data
        timings[index].append(get_exp_timing_timeit(ct,key,key1["n"],pred_reps))      
        #print(index)      
    return (get_oracle_timing_timeit(oracle,ct,actual_reps))

def time_samples_method_three(sample_keys,ct,key1,pred_reps,oracle,actual_reps,timings,actual_timing):
    for index,key in enumerate(sample_keys): #gets samples amount of timing data
        timings[index].append(get_exp_timing_timeit_repeat(ct,key,key1["n"],pred_reps))      
        #print(index)      
    return (get_oracle_timing_timeit_repeat(oracle,ct,actual_reps))

def time_samples_method_four(sample_keys,ct,key1,pred_reps,oracle,actual_reps,timings,actual_timing):
    actual_timings_arr = [0 for _ in range(len(sample_keys))]
    for index,key in enumerate(sample_keys): #gets samples amount of timing data
        timings[index].append(get_exp_timing_timeit_repeat(ct,key,key1["n"],pred_reps))
        actual_timings_arr.append[(get_oracle_timing_timeit_repeat(oracle,ct,actual_reps))]      
        #print(index)      
    return np.mean(actual_timings_arr)

def solve_specific_bit(prefix):
    prefix_len = len(prefix)
    prefix = int(prefix)
    bits = 1
    numkeys = 100
    numcts = 1
    result = ''
    key_arrs = []
    sample_keys = [uva_rsa.rsa_gen()["d"] for _ in range(numkeys)]
    mask = (1 << (2048 - prefix_len)) - 1  # Create a mask to preserve the remaining bits
    sample_keys = [(prefix << (2048 - prefix_len)) | (num & mask) for num in sample_keys] #generate sample keys
    sample_keys_str = [format(key, 'b').zfill(2048) for key in sample_keys]
    pred_reps = 25
    actual_reps = 25
    samples = 10
    actual_samples = 25
    char_zero_keys = []
    char_one_keys = []
    
    #print("initialize: ")
    char_one_keys = [sample_keys[i] for i in range(len(sample_keys)) if str(sample_keys_str[i][prefix_len]) == '1']  #keys with bit 1 at index "bit"
    char_zero_keys = [sample_keys[i] for i in range(len(sample_keys)) if str(sample_keys_str[i][prefix_len])== '0'] #keys with bit 0 at index "bit"

    #cts = [uva_rsa.rsa_enc(key1["e"],key1["n"],random.randrange(0,2**2048-1)) for _ in range(numcts)]
    cts = [2 for _ in range(numcts)]
    predictions = [0 for _ in range(2)]


    for ct in range(numcts):
        actual_timing = []
        timings = [[] for _ in range(len(sample_keys))]
        #print("sample timing")

        #actual_timing = time_samples_method_one(samples,sample_keys,pred_reps,actual_reps,timings,oracle,ct,key1)

        #actual_timing = time_samples_method_two(sample_keys,ct,key1,pred_reps,oracle,actual_reps,timings,actual_timing)

        actual_timing = time_samples_method_three(sample_keys,ct,key1,pred_reps,oracle,actual_reps,timings,actual_timing)

        #print("making preds")

        ones_longer_than_zeros = 0

        bit = prefix_len
        ones_timing = np.mean([t for ind,t in enumerate(timings) if sample_keys[ind] in char_one_keys])
        zeros_timing = np.mean([t for ind,t in enumerate(timings) if sample_keys[ind] in char_zero_keys])
        #print(f"bits: {bit}")
        
        #if ones_timing: #print(f"ones timing avg: {ones_timing}")
        #if zeros_timing: #print(f"zeros timing avg: {zeros_timing}")
        #print(f"actual timing: {actual_timing}")
        if np.isnan(ones_timing):
            predictions[0] = predictions[0] + 1 #if there are no sample keys that have a certain bit at a certain position, auto choose that bit
            #print("no ones, predicting zero")
        elif np.isnan(zeros_timing):
            predictions[1] = predictions[1] + 1 
            #print("no zeros, predicting one")
        elif abs(actual_timing - ones_timing) < abs(actual_timing - zeros_timing): #else calculate
            predictions[1] = predictions[1] + 1
            #print("predicting one")
        else:
            #print("predicting zero")
            predictions[0] = predictions[0] + 1

        if ones_timing > zeros_timing: ones_longer_than_zeros+=1

    pred = predictions
    result = '1' if pred[1] > pred[0] else '0'

    #print(f"ones take longer than zeros percentage: {ones_longer_than_zeros/bits}")


    #print(f"guessing: {result}")

    return result

def solve_for_n_bits(bits):
    prefix = '0'
    for _ in range(bits):
        prefix += solve_specific_bit(prefix)
    return prefix

########################################################### 
# Problem 1: 6-bit Prefix
# Recover the first 6 bits of the secret key
########################################################### 
def problem1(pub_e, pub_n, oracle):
    #
    # Write your solution here.
    # Call oracle.run_6bits(...) with same or different inputs,
    # and then use the consumed time to recover the 6 bits.
    #

    #Implementation 1 -> theoretically gets answer 1/10 vs 1/100 times
    all_bitstrings = [i << 2042 for i in range(64)]
    all_oracles = [uva_rsa.DecryptOracleA(bitstring,pub_n) for bitstring in all_bitstrings]

    reps = 1000
    res_list = [0 for _ in range(64)]

    potential_cts = [i<<2042 for i in range(64)]
    for _ in range(25):
        potenital_sk_timings = []
        ct = secrets.randbits(2048)
        for potential_oracle in all_oracles:
            potential_timing = get_decrypt_timing(reps, potential_oracle, ct)
            potenital_sk_timings.append(potential_timing)

        #print(potenital_sk_timings)

        actual_timing = get_decrypt_timing(reps,oracle,ct)
        #print(actual_timing)

        closest_index,closest_value , = min(enumerate(potenital_sk_timings), key=lambda timing: abs(timing[1] - actual_timing))
        
        if closest_index > 63:
            print(f"index: {closest_index}, time: {closest_value}")
            print(potenital_sk_timings)
        
        print(closest_index)
        res_list[closest_index] = res_list[closest_index] + 1

    # print(f"Reps: {reps}")
    # for index, value in enumerate(res_list):
    #     print(f"Index: {index}, Value: {value}")

    return res_list.index(max(res_list))    

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
    return solve_for_n_bits(2)

########################################################### 
# Problem 3: The whole 2048 bits
# Recover the (roughly) 2048 bits of the secret key
########################################################### 
def problem3(pub_e, pub_n, oracle):
    return solve_for_n_bits(2047)

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
