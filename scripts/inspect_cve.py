import json

with open(
    "data/raw/vulnerability_master.json",
    "r",
    encoding="utf-8"
) as f:
    data = json.load(f)


for cve in data[:5]:

    print("\n" + "=" * 80)
    print("CVE:", cve["id"])

    print("\nDescription:")
    for description in cve.get("descriptions", []):
        if description["lang"] == "en":
            print(description["value"])

    print("\nAffected products:")

    for affected_source in cve.get("affected", []):
        for product in affected_source.get("affectedData", []):
            print(
                f"  Vendor: {product.get('vendor')}"
            )
            print(
                f"  Product: {product.get('product')}"
            )

    print("\nCVSS:")

    for metric in cve.get("metrics", {}).get("cvssMetricV31", []):
        cvss = metric["cvssData"]

        print(
            f"  Score: {cvss.get('baseScore')}"
        )
        print(
            f"  Severity: {cvss.get('baseSeverity')}"
        )

    print()