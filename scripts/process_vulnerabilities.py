import json
import os


# --------------------------------------------------
# Load filtered vulnerability data
# --------------------------------------------------

with open(
    "data/raw/vulnerability_master.json",
    "r",
    encoding="utf-8"
) as f:
    vulnerabilities = json.load(f)


# --------------------------------------------------
# Store processed vulnerabilities
# --------------------------------------------------

processed_vulnerabilities = []


# --------------------------------------------------
# Process each CVE
# --------------------------------------------------

for cve in vulnerabilities:

    # ----------------------------------------------
    # Basic information
    # ----------------------------------------------

    cve_id = cve.get("id")

    published = cve.get("published")

    last_modified = cve.get("lastModified")

    vuln_status = cve.get("vulnStatus")


    # ----------------------------------------------
    # Description
    # ----------------------------------------------

    description = ""

    for item in cve.get("descriptions", []):

        if item.get("lang") == "en":
            description = item.get("value", "")
            break


    # ----------------------------------------------
    # Affected products
    # ----------------------------------------------

    affected_products = []

    for source in cve.get("affected", []):

        for product in source.get("affectedData", []):

            vendor = product.get("vendor")
            product_name = product.get("product")

            versions = []

            for version in product.get("versions", []):

                version_info = {
                    "version": version.get("version"),
                    "status": version.get("status"),
                    "lessThan": version.get("lessThan"),
                    "lessThanOrEqual": version.get(
                        "lessThanOrEqual"
                    ),
                    "versionType": version.get(
                        "versionType"
                    )
                }

                versions.append(version_info)


            affected_products.append({
                "vendor": vendor,
                "product": product_name,
                "defaultStatus": product.get(
                    "defaultStatus"
                ),
                "versions": versions
            })


    # ----------------------------------------------
    # CVSS information
    # ----------------------------------------------

    cvss_score = None
    severity = None
    vector = None

    cvss_metrics = cve.get(
        "metrics",
        {}
    ).get(
        "cvssMetricV31",
        []
    )


    if cvss_metrics:

        # Prefer NVD's primary metric
        primary_metric = None

        for metric in cvss_metrics:

            if metric.get("type") == "Primary":
                primary_metric = metric
                break


        # Fall back to the first metric
        if primary_metric is None:
            primary_metric = cvss_metrics[0]


        cvss_data = primary_metric.get(
            "cvssData",
            {}
        )

        cvss_score = cvss_data.get("baseScore")

        severity = cvss_data.get("baseSeverity")

        vector = cvss_data.get("vectorString")


    # ----------------------------------------------
    # Weakness / CWE
    # ----------------------------------------------

    weaknesses = []

    for weakness in cve.get("weaknesses", []):

        for description_item in weakness.get(
            "description",
            []
        ):

            if description_item.get("lang") == "en":

                weaknesses.append(
                    description_item.get("value")
                )


    # ----------------------------------------------
    # References
    # ----------------------------------------------

    references = []

    for reference in cve.get(
        "references",
        []
    ):

        references.append({
            "url": reference.get("url"),
            "source": reference.get("source"),
            "tags": reference.get("tags", [])
        })


    # ----------------------------------------------
    # Create clean record
    # ----------------------------------------------

    processed_cve = {

        "cve_id": cve_id,

        "published": published,

        "last_modified": last_modified,

        "status": vuln_status,

        "description": description,

        "affected_products": affected_products,

        "cvss": {
            "score": cvss_score,
            "severity": severity,
            "vector": vector
        },

        "weaknesses": weaknesses,

        "references": references
    }


    processed_vulnerabilities.append(
        processed_cve
    )


# --------------------------------------------------
# Create output directory
# --------------------------------------------------

os.makedirs(
    "data/processed",
    exist_ok=True
)


# --------------------------------------------------
# Save processed data
# --------------------------------------------------

output_file = (
    "data/processed/vulnerabilities.json"
)

with open(
    output_file,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        processed_vulnerabilities,
        f,
        indent=4,
        ensure_ascii=False
    )


# --------------------------------------------------
# Summary
# --------------------------------------------------

print(
    "Processed vulnerabilities:",
    len(processed_vulnerabilities)
)

print(
    "Saved to:",
    output_file
)