import requests
import json
import time

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

all_vulnerabilities = []

start_index = 0
results_per_page = 100

while True:

    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "pubStartDate": "2026-08-01T00:00:00.000",
        "pubEndDate": "2026-09-06T23:59:59.999"
    }

    print(f"\nRequesting records {start_index} - {start_index + results_per_page}...")

    try:
        response = requests.get(
            url,
            params=params,
            timeout=30
        )

        response.raise_for_status()

    except requests.exceptions.RequestException as e:
        print("Request failed:", e)
        print("Waiting 10 seconds before retrying...")
        time.sleep(10)
        continue

    data = response.json()

    vulnerabilities = data["vulnerabilities"]

    all_vulnerabilities.extend(vulnerabilities)

    print(
        f"Downloaded {len(all_vulnerabilities)} / "
        f"{data['totalResults']} vulnerabilities"
    )

    if start_index + len(vulnerabilities) >= data["totalResults"]:
        break

    start_index += len(vulnerabilities)

    # Wait between requests
    time.sleep(1)


print("\nTotal vulnerabilities downloaded:", len(all_vulnerabilities))


#saving file
# Save everything
with open(
    "data/raw/nvd_cves.json",
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        all_vulnerabilities,
        f,
        indent=4
    )

print("Saved to data/raw/nvd_cves.json")


