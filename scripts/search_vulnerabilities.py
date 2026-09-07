import json


# --------------------------------------------------
# Load processed vulnerabilities
# --------------------------------------------------

with open(
    "data/processed/vulnerabilities.json",
    "r",
    encoding="utf-8"
) as f:
    vulnerabilities = json.load(f)


# --------------------------------------------------
# Search function
# --------------------------------------------------

def search_vulnerabilities(query):

    query = query.lower()

    results = []

    for cve in vulnerabilities:

        # Search in CVE ID
        if query in cve["cve_id"].lower():
            results.append(cve)
            continue

        # Search in description
        if query in cve["description"].lower():
            results.append(cve)
            continue

        # Search affected products
        for product in cve["affected_products"]:

            vendor = product.get("vendor") or ""
            product_name = product.get("product") or ""

            if query in vendor.lower():
                results.append(cve)
                break

            if query in product_name.lower():
                results.append(cve)
                break

    return results


# --------------------------------------------------
# Test search
# --------------------------------------------------

query = input("Search vulnerabilities: ")

results = search_vulnerabilities(query)


print(
    f"\nFound {len(results)} vulnerabilities.\n"
)


# --------------------------------------------------
# Display results
# --------------------------------------------------

for cve in results[:20]:

    print("=" * 60)

    print("CVE:", cve["cve_id"])

    print(
        "Severity:",
        cve["cvss"]["severity"]
    )

    print(
        "Score:",
        cve["cvss"]["score"]
    )

    print(
        "Description:",
        cve["description"]
    )

    print()