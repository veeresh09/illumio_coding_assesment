import random

# Define protocol options and initial tag set
protocols = ["icmp","igmp","tcp","udp","gre","esp","ah","pim","sctp","dccp","eigrp","ospfigp",
             "eigrp","l2tp","mpls-in-ip","rsvp","vrrp","wesp","etherip"]

# Create a set to store unique combinations
unique_combinations = set()

# Generate unique combinations
while len(unique_combinations) < 10000:
    dstport = random.randint(0, 65535)  # Valid port range 0-65535
    protocol = random.choice(protocols)
    tag = f"sv_{random.randint(1, 10000):04d}"
    combination = (dstport, protocol, tag)
    # Add to the set (sets automatically ensure uniqueness)
    if combination not in unique_combinations:
        unique_combinations.add(combination)
# Write to a text file
with open('unique_lookup_table.txt', 'w') as f:
    for combo in unique_combinations:
        f.write(f"{combo[0]},{combo[1]},{combo[2]}\n")