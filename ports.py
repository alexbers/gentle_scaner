import random
import time
import hashlib

# time of full rescan in days
DAYS_IN_FULL_SCAN = 1

RANDOM_STRING = "changeme"


PORTS_10MIN_RESCAN = [
    21, 22, 23, 25, 53, 80, 110, 111, 123, 135,
    139, 143, 161, 389, 443, 445, 554, 636, 993, 995,
    1025, 1443, 2049, 3306, 3389, 4444, 5432, 5900, 8000, 8443,
    8080, 8888
]

PORTS_1HOUR_RESCAN = [
    587, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 32768, 26,
    49152, 2001, 515, 8008, 49154, 1027, 5666, 5000, 5631, 631, 49153, 8081, 88, 79, 5800,
    106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 144, 7, 8009,
    3128, 444, 9999, 5009, 7070, 5190, 3000, 1900, 3986, 13, 1029, 9, 6646, 5051,
    49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001, 5001, 82, 10010, 1030,
    9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255, 1056, 1049, 1065, 2967,
    1053, 1048, 1064, 1054, 3703, 17, 808, 3689, 1031, 1044, 1071, 5901, 100, 9102, 8010,
    1039, 4001, 2869, 9000, 5120, 2105, 1038, 2601, 1, 7000, 1066, 1069, 625, 311, 280,
    254, 4000, 1761, 5003, 2002, 1998, 2005, 1032, 1050, 6112, 3690, 1521, 2161, 6002, 1080,
    2401, 4045, 902, 787, 7937, 1058, 2383, 32771, 1059, 1040, 1033, 50000, 5555, 10001,
    1494, 593, 3, 2301, 7938, 3268, 1234, 1022, 1074, 9001, 8002, 1036, 1035, 1037, 464,
    1935, 497, 6666, 2003, 6543, 24, 1352, 3269, 1111, 407, 500, 20, 2006, 1034, 3260, 15000,
    1218, 264, 2004, 33, 42510, 1042, 3052, 999, 1023, 222, 1068, 7100, 888, 563, 1717, 992,
    32770, 2008, 32772, 7001, 2007, 8082, 5550, 5801, 2009, 512, 1043, 50001, 2701, 1700,
    7019, 4662, 2065, 2010, 42, 2602, 9535, 3333, 5100, 5002, 2604, 4002, 6059, 1062,
    9415, 8701, 8652, 8651, 8089, 65389, 65000, 64680, 64623, 55600, 55555, 52869, 35500,
    33354, 23502, 20828, 8194, 8193, 8192, 2702, 1311, 1060, 4443, 9595, 1051, 3283, 1047,
    9594, 6789, 5226, 5225, 32769, 1052, 9593, 1055, 16993, 16992, 13782, 1067, 5902, 366,
    9050, 1002, 85, 5500, 8085, 51103, 49999, 45100, 10243, 5431, 1864, 1863, 49, 6667, 90,
    1503, 27000, 6881, 1500, 340, 8021, 5566, 9071, 8088, 8899, 2222, 6005, 32773, 32774,
    9876, 1501, 9101, 5102, 163, 5679, 648, 1666, 146, 901, 83, 8084, 9207, 8001, 8083,
    5214, 14238, 3476, 5004, 30, 12345, 912, 2030, 2605, 6, 541, 4, 1248, 3005, 8007, 880, 306,
    2500, 4242, 8291, 52822, 1097, 9009, 2525, 1086, 1088, 900, 6101, 7200, 2809, 987, 32775,
    800, 12000, 1083, 211, 705, 711, 20005, 13783, 6969, 1104, 5269, 5222, 1046, 1085, 5987,
    5989, 5988, 9968, 9503, 9502, 9485, 9290, 9220, 8994, 8649, 8222, 7911, 7625, 7106, 65129,
    63331, 6156, 6129, 60020, 5962, 5961, 5960, 5959, 5925, 5877, 5825, 5810, 58080, 57294,
    50800, 50006, 50003, 49160, 49159, 49158, 48080, 40193, 34573, 34572, 34571, 3404,
    33899, 3301, 32782, 32781, 31038, 30718, 28201, 27715, 25734, 24800, 22939, 21571, 20221,
    20031, 19842, 19801, 19101, 17988, 1783, 16018, 16016, 15003, 14442, 13456, 10629, 10628,
    10626, 10621, 10617, 10616, 10566, 10025, 10024, 10012, 1169, 2190, 11967, 5030, 5414,
    1057, 7627, 6788, 3766, 8087, 11110, 1947, 9010, 7741, 14000, 3367, 1094, 1099, 1098,
    1075, 1108, 4003, 1081, 1093, 4449, 2718, 6580, 15002, 4129, 1687, 1840, 3827, 30000,
    3580, 1100, 2144, 1063, 1061, 6901, 9900, 1107, 1106, 9500, 20222, 7778, 8181, 1077,
    3801, 1310, 1718, 2119, 2811, 2492, 2135, 1070, 9080, 1045, 16001, 2399, 3017, 3031,
    1148, 9002, 8873, 2875, 5718, 10002, 3998, 20000, 4126, 9011, 8086, 8400, 1272, 3071, 5911,
    2607, 9618, 2381, 1096, 5910, 6389, 3300, 7777, 1072, 3351, 1073, 8333, 3784, 15660, 5633,
    6123, 3211, 1078, 8600, 1079, 3659, 3551, 2260, 2160, 1082, 2100, 3325, 3323, 8402, 89, 691,
    2020, 1001, 1999, 32776, 212, 6003, 2998, 50002, 7002, 32, 898, 5510, 3372, 2033, 5903, 99,
    749, 425, 43, 5405, 6502, 13722, 6106, 458, 7007, 9666, 8100, 3737, 5280, 9091, 4111, 9877,
    1334, 3261, 1152, 2522, 5859, 2179, 1247, 9944, 9943, 9110, 8654, 8254, 8180, 8011, 7512,
    7435, 7103, 61900, 61532, 5922, 5915, 5904, 5822, 56738, 55055, 51493, 50636, 50389, 49175,
    49165, 49163, 3546, 32784, 27355, 27353, 27352, 24444, 19780, 18988, 16012, 15742, 10778,
    2191, 3011, 1580, 5200, 3851, 3371, 3370, 3369, 7402, 5054, 4006, 5298, 3918, 2126, 3077,
    7443, 8090, 3493, 3828, 4446, 1186, 1183, 19283, 19315, 3995, 62078, 5963, 3880, 1124, 1782,
    8500, 1089, 10004, 1296, 9998, 2251, 1087, 3871, 3030, 9040, 32779, 32777, 1021, 32778, 2021,
    616, 700, 666, 5802, 4321, 1112, 38292, 2040, 1524, 545, 84, 49400, 32780, 2111, 1600, 2048,
    3006, 1084, 2638, 6547, 16080, 6699, 9111, 6007, 1533, 720, 2034, 5560, 2106, 555, 667,
    801, 3221, 6025, 3826, 9200, 2608, 4279, 7025, 11111, 4445, 9917, 9575, 9099, 9003, 8290, 8099, 8093, 8045,
    7921, 7920
]

PORTS_24HOUR_RESCAN = list(set(range(1,65536)) - set(PORTS_10MIN_RESCAN) - set(PORTS_1HOUR_RESCAN))


def gen_base_port_sequence():
    RANDOM_SEED = 42

    ports_count = len(PORTS_24HOUR_RESCAN) + len(PORTS_1HOUR_RESCAN) * 24 + len(PORTS_10MIN_RESCAN) * 24 * 6

    ports = []

    bucket_24hours = PORTS_24HOUR_RESCAN[:]

    for hour in range(24):
        bucket_1hour = PORTS_1HOUR_RESCAN[:]
        for ten_mins in range(6):
            bucket_10mins = PORTS_10MIN_RESCAN[:]
            for secs in range(60*10):
                if bucket_10mins:
                    ports.append(bucket_10mins.pop())
                elif bucket_1hour:
                    ports.append(bucket_1hour.pop())
                elif bucket_24hours:
                    ports.append(bucket_24hours.pop())
    assert len(ports) == ports_count

    rnd = random.Random(RANDOM_SEED)

    # shuffle ports in 10 minute intervals
    shuffled_ports = []
    for idx in range(0, len(ports) + 1, 60*10):
        ten_mins = ports[idx:idx+60*10]

        rnd.shuffle(ten_mins)
        shuffled_ports += ten_mins
    ports = shuffled_ports

    # shuffle ports in 1 hour intervals
    shuffled_ports = []
    for idx in range(0, len(ports) + 1, 60*60):
        one_hour = ports[idx:idx+60*60]

        rnd.shuffle(one_hour)
        shuffled_ports += one_hour
    ports = shuffled_ports
    assert len(ports) == ports_count

    return ports

BASE_PORT_SEQUENCE = gen_base_port_sequence()

def unpredictable_hash(obj, modulo):
    return int.from_bytes(hashlib.sha256((str(obj)+RANDOM_STRING).encode()).digest(), "little") % modulo


# generates the port sequence based on the current time
# returns [(port, time), ...]
def gen_ports(start_time=None):
    if not start_time:
        start_time = int(time.time())

    start_day = start_time // (86400*DAYS_IN_FULL_SCAN)
    day_sec = start_time % (86400*DAYS_IN_FULL_SCAN)
    item_num = day_sec // DAYS_IN_FULL_SCAN

    day_ports_offset = unpredictable_hash(start_day, len(BASE_PORT_SEQUENCE))

    while True:
        if item_num >= len(BASE_PORT_SEQUENCE):
            start_day += 1
            day_ports_offset = unpredictable_hash(start_day, len(BASE_PORT_SEQUENCE))
            item_num = 0

        port = BASE_PORT_SEQUENCE[(item_num+day_ports_offset) % len(BASE_PORT_SEQUENCE)]
        timestamp = start_day*86400*DAYS_IN_FULL_SCAN + item_num*DAYS_IN_FULL_SCAN

        # add random deley to unsyncronize port scans
        timestamp += random.random() * DAYS_IN_FULL_SCAN
        yield (port, timestamp)
        item_num += 1
