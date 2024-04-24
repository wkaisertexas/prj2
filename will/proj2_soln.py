import uva_rsa 
import secrets
import time
import random
import timeit

import matplotlib.pyplot as plt

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
    start = timeit.default_timer()
    for _ in range(reps):
        oracle.run_6bits(ct)
    end = timeit.default_timer()
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
    # getting the basis
    secret_key = 0xABCD0123
    reps = 100
    ct = uva_rsa.rsa_enc(pub_e, pub_n, secret_key)

    for _ in range(3): # warmup for python JIT
        oracle.run(ct)
    
    samples_times = []
    for _ in range(reps):
        start = time.perf_counter_ns()
        oracle.run(ct)
        end = time.perf_counter_ns()
        samples_times.append(end - start)

    samples_times = sorted(samples_times)
    baseline = samples_times[len(samples_times) // 2] # getting the median (outlier resistant)
    print("time to decrypt with oracle", baseline)

    reps = 50
    times = []
    for i in range(8):
        secret_key = 0xABCD0123 + i << 2045
        ct = uva_rsa.rsa_enc(pub_e, pub_n, secret_key)

        for _ in range(3): # warmup for python JIT
            uva_rsa.mod_exp(ct, secret_key, pub_n)

        sample_times = []
        for _ in range(reps):
            start = time.perf_counter_ns()
            uva_rsa.mod_exp(ct, secret_key, pub_n)
            end = time.perf_counter_ns()
            sample_times.append(end - start)
        
        sample_times = sorted(sample_times)
        avg_time = sample_times[len(sample_times) // 2] # getting the median (outlier resistant)
        print("Index", i, "Average time", avg_time)
        times.append(avg_time)
    # print((end - start)/reps) ### print only for testing purpose, not needed in your submission  

    diff_array = [abs(baseline - time) for time in times]
    min_bit_index = diff_array.index(min(diff_array))

    print(sorted(diff_array))
    print([diff_array.index(item) for item in sorted(diff_array)])
    print("Min bit", min(diff_array))
    print("Min bit index", min_bit_index)

    times = list(map(lambda x: x / 1_000_000_000, times))

    return min_bit_index

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
    benchmark = (end - start)/reps ### print only for testing purpose, not needed in your submission  
    print("Benchmark", benchmark)

    # secret_keys = [uva_rsa.rsa_gen()['d'] for _ in range(100)]
    secret_keys = [random.randrange(0, 2**2048 - 1) for _ in range(300)]
    one_times = [0] * 2048
    zero_times = [0] * 2048

    one_counts = [0] * 2048
    zero_counts = [0] * 2048

    reps = 50
    # print(secret_keys)

    for key in secret_keys:
        bits = format(key, 'b')
        bits = bits.zfill(2048)

        for i, bit in enumerate(bits):
            if bit == "0":
                zero_counts[i] += 1
            else:
                one_counts[i] += 1

    for i, key in enumerate(secret_keys):
        # ct = uva_rsa.rsa_gen()['d']
        ct = random.randrange(0, 2**2048 - 1)

        # jit prevention
        for _ in range(10):
            uva_rsa.mod_exp(key, pub_n, ct)


        start = time.perf_counter_ns()
        for _ in range(reps):
            uva_rsa.mod_exp(key, pub_n, ct)
        end = time.perf_counter_ns()

        time_taken = (end - start) / reps
        print(f"{i} Time taken {time_taken/1_000_000:.1f}")

        bits = format(key, 'b')
        bits = bits.zfill(2048)

        # print(bits)
        for j, bit in enumerate(bits):
            pass
            if bit == "0":
                zero_times[j] += time_taken / zero_counts[j]
            else:
                one_times[j] += time_taken / one_counts[j]


        # print("One Times", one_times)
        # print("Zero Times", zero_times)

    for i in range(100):
        print("0", zero_times[i], "1", one_times[i], "time", benchmark)

    d = 4150452954516788305322334373505934224092414147025341858259381425646659178605691706486212654370727684626846117494529293210823262969746501329504015330861438248564932422166878714870792714969678806278402238259157411843640134215067682273010431589510827287426792759999212883054785908980030403151122652491713875272966953950697706468122810899702465849201975767642644740088526762001961677935216877828845320587721250185528209814840248616253000685484141272453417580384407258920262649904440074465914446977660642607238586680208905768616792883391776390693711645020742189552372320510460581645319646313943217496379479242398240521369
    bits = format(d, 'b')
    bits = bits.zfill(2048)

    correct = 0
    for i in range(2048):
        true_val = bits[i]

        time_diff_0 = abs(zero_times[i] - benchmark)
        time_diff_1 = abs(one_times[i] - benchmark)

        if true_val == "0":
            correct += 1 if time_diff_0 < time_diff_1 else 0
        else:
            correct += 1 if time_diff_1 < time_diff_0 else 0

    print(f"PERCENT CORRECT { 100 * correct / 2048:.2f}%")

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
    # print("Problem 1:")
    # oracle = uva_rsa.DecryptOracleA(key["d"], key["n"])
    # print(uva_rsa.prefix(key["d"], 6))
    # if problem1(key["e"], key["n"], oracle) == uva_rsa.prefix(key["d"], 6):
    #     print("Problem 1 correct")

    # Problem 2
    print("Problem 2:")
    # oracle = uva_rsa.DecryptOracleB(key["d"], key["n"])
    # print("Target value:", uva_rsa.prefix(key["d"], 3))
    # if problem2(key["e"], key["n"], oracle) == uva_rsa.prefix(key["d"], 3):
    #     print("Problem 2 correct")

    # Problem 3
    print("Problem 3:")
    # oracle = uva_rsa.DecryptOracleB(key["d"], key["n"])
    # if problem3(key["e"], key["n"], oracle) == key["d"]:
    #     print("Problem 3 correct")
