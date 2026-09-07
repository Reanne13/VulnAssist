import json


with open(
    "data/processed/vulnerabilities.json",
    "r",
    encoding="utf-8"
) as f:
    vulnerabilities = json.load(f)


print("Total vulnerabilities:", len(vulnerabilities))


for cve in vulnerabilities[:5]:

    print("\n" + "=" * 60)

    print("CVE:", cve["cve_id"])
    print("Published:", cve["published"])
    print("Status:", cve["status"])

    print("\nDescription:")
    print(cve["description"])

    print("\nAffected Products:")

    for product in cve["affected_products"]:

        print(
            "  Vendor:",
            product["vendor"]
        )

        print(
            "  Product:",
            product["product"]
        )

        print(
            "  Default Status:",
            product["defaultStatus"]
        )

        print(
            "  Versions:",
            product["versions"]
        )

    print("\nCVSS:")

    print(
        "  Score:",
        cve["cvss"]["score"]
    )

    print(
        "  Severity:",
        cve["cvss"]["severity"]
    )

    print(
        "  Vector:",
        cve["cvss"]["vector"]
    )

    print("\nWeaknesses:")
    print(cve["weaknesses"])

    print("\nReferences:")

    for reference in cve["references"][:3]:
        print(
            "  ",
            reference["url"]
        )