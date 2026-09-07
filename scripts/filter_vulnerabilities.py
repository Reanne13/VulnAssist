import json

# Load downloaded NVD data
with open(
    "data/raw/nvd_cves.json",
    "r",
    encoding="utf-8"
) as f:
    data = json.load(f)


# Products/vendors we are interested in
TARGETS = [
    "windows",
    "postgresql",
    "openssl",
    "cisco",
    "tomcat",
    "apache"
]


# Store matching vulnerabilities
filtered_vulnerabilities = []


# Go through every vulnerability
for vulnerability in data:

    cve = vulnerability["cve"]

    found_match = False

    # Look through configurations
    for config in cve.get("configurations", []):

        for node in config.get("nodes", []):

            for match in node.get("cpeMatch", []):

                # Ignore CPEs that are not vulnerable
                if not match.get("vulnerable", False):
                    continue

                criteria = match.get("criteria", "").lower()

                # Check whether our target appears in the vulnerable CPE
                for target in TARGETS:

                    if target in criteria:

                        filtered_vulnerabilities.append(cve)

                        print(
                            cve["id"],
                            "->",
                            criteria
                        )

                        found_match = True
                        break

                if found_match:
                    break

            if found_match:
                break

        if found_match:
            break


print(
    "\nTotal matching vulnerabilities:",
    len(filtered_vulnerabilities)
)


# Save filtered vulnerabilities
with open(
    "data/raw/vulnerability_master.json",
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        filtered_vulnerabilities,
        f,
        indent=4
    )

print(
    "Saved filtered vulnerabilities to "
    "data/raw/vulnerability_master.json"
)