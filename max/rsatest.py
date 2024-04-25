import timeit
import uva_rsa
import secrets
import random

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

def mod_exp(base, exponent, modulus):
    bits = format(exponent, 'b')
    y = 1
    for b in bits:
        y = (y * y) % modulus
        if '1' == b:
            y = (y * base) % modulus
    return y

def get_exp_timing(base,exponent,modulus,reps):
    start = timeit.default_timer()
    for i in range(reps):
        mod_exp(base,exponent,modulus)
        #print(i)
    end = timeit.default_timer()
    return (end-start)/(reps)

def get_oracle_timing(oracle,ct,reps):
    start = timeit.default_timer()
    for i in range(reps):
        oracle.run(ct)
        #print(i)
    end = timeit.default_timer()
    return (end-start)/(reps)
                   
    

pub_e = 65537
pub_n = 26334846008439167556765994336545761339068098619101850421771908459419918602128141355234077943248935530058859245371916765929458717691408496374069803243864206525054456891054239459424634162712907872176687992073038190824711743119057398524481757063408686486317239808826593650469866307923539528308953119230902384306178943542441126686061578352279102334653866502920311536313397546287885026738627086034614799371467801646963827587890747711299932470791488642354928910842955461742067813873505900679667440625963269380243732319252322289624537679679000548719937080897079171234468074929759669376046003568677119493377927698383184444971
key1 = {"e": 65537,
"n": 26334846008439167556765994336545761339068098619101850421771908459419918602128141355234077943248935530058859245371916765929458717691408496374069803243864206525054456891054239459424634162712907872176687992073038190824711743119057398524481757063408686486317239808826593650469866307923539528308953119230902384306178943542441126686061578352279102334653866502920311536313397546287885026738627086034614799371467801646963827587890747711299932470791488642354928910842955461742067813873505900679667440625963269380243732319252322289624537679679000548719937080897079171234468074929759669376046003568677119493377927698383184444971,
"d": 4150452954516788305322334373505934224092414147025341858259381425646659178605691706486212654370727684626846117494529293210823262969746501329504015330861438248564932422166878714870792714969678806278402238259157411843640134215067682273010431589510827287426792759999212883054785908980030403151122652491713875272966953950697706468122810899702465849201975767642644740088526762001961677935216877828845320587721250185528209814840248616253000685484141272453417580384407258920262649904440074465914446977660642607238586680208905768616792883391776390693711645020742189552372320510460581645319646313943217496379479242398240521369}
key = key1
oracle = uva_rsa.DecryptOracleB(key["d"], key["n"])
ct = int('1'*2048,2)#uva_rsa.rsa_enc(pub_e, pub_n, 0xffffff)

all_bitstrings = [i << 2045 for i in range(64)]
#all_bitstrings = [int('1' + '0'*2047,2),int('01' + '0'*2046,2),int('001' + '0'*2045,2),int('0001' + '0'*2044,2),int('00001' + '0'*2043,2),int('000001' + '0'*2041,2)]
#all_oracles = [uva_rsa.DecryptOracleA(bitstring,pub_n) for bitstring in all_bitstrings]
def test2():
    reps = 10000
    mod_exp_timings = 123

def time_all_mod_exps():
    reps = 10000

    mod_exp_vals = [mod_exp(2,exp,key1["e"]) for exp in range(32)]
    bits = secrets.randbits(200)
    mod_exp_timings = [get_exp_timing(base,bits,key1["e"],reps) for base in mod_exp_vals]

    print(mod_exp_vals)
    return mod_exp_timings

def solve_p2(bits):
    numkeys = 100
    numcts = 5
    result = ''
    key_arrs = []
    sample_keys = [uva_rsa.rsa_gen()["d"] for _ in range(numkeys)]
    sample_keys_str = [format(key, 'b').zfill(2047) for key in sample_keys]
    pred_reps = 100
    actual_reps = 1000

    for bit in range(bits):
        char_one_keys = [sample_keys[i] for i in range(len(sample_keys)) if str(sample_keys_str[i])[bit] == '1']
        char_zero_keys = [sample_keys[i] for i in range(len(sample_keys)) if str(sample_keys_str[i])[bit] == '0']
        key_arrs.append((char_zero_keys,char_one_keys))

    cts = [uva_rsa.rsa_enc(key1["e"],key1["n"],random.randrange(0,2**2048-1)) for _ in range(numcts)]
    predictions = [[0 for _ in range(2)] for _ in range(bits)]


    for ct in range(numcts):
        timings = [0 for _ in range(len(sample_keys))]
        print("sample timing")
        for index,key in enumerate(sample_keys):
            print(index)
            timings[index] = get_exp_timing(ct,key,key1["n"],pred_reps)

        print("actual timing")
        actual_timing = get_oracle_timing(oracle,ct,actual_reps)

        print("making preds")
        for bit in range(bits):
            ones_timing = [t for ind,t in enumerate(timings) if sample_keys[ind] in char_one_keys]
            zeros_timing = [t for ind,t in enumerate(timings) if sample_keys[ind] in char_zero_keys]
            if abs(actual_timing - sum(ones_timing)/len(ones_timing)) < abs(actual_timing - sum(zeros_timing)/len(zeros_timing)):
                predictions[bit][1] = predictions[bit][1] + 1
            else:
                predictions[bit][0] = predictions[bit][0] + 1

    for pred in predictions:
        result += '1' if pred[1] > pred[0] else '0'

        # actual_timing = 0
        # zeros_timing = 0
        # ones_timing = 0
        # print(f"ct: {ct}")
        # print("ones_timing")
        # for sample_key in char_one_keys:
            
        #     ones_timing += get_exp_timing(ct,sample_key,key["n"],sample_reps)
            
        # ones_timing /= len(char_one_keys)
        # print("zeros_timing")
        # for sample_key in char_zero_keys:
            
        #     zeros_timing += get_exp_timing(ct,sample_key,key["n"],sample_reps)

        # zeros_timing /= len(char_zero_keys)
        #print("actual_timing")
        # actual_timing += get_oracle_timing(oracle,ct,actual_reps)
        # if abs(actual_timing-ones_timing) < abs(actual_timing-zeros_timing):
        #     ones_pred+=1
        # else:
        #     zeros_pred+=1
    # print(abs(actual_timing-ones_timing), abs(actual_timing-zeros_timing))
    # result += '1' if ones_pred > zeros_pred else '0'
    #result += '1' if abs(actual_timing-ones_timing) < abs(actual_timing-zeros_timing) else '0'
    print(f"guessing: {result}")

    return int(result,2)

print(solve_p2(3))