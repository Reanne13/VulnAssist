import json
import os

import chromadb
from sentence_transformers import SentenceTransformer


# --------------------------------------------------
# 1. Load vulnerability data
# --------------------------------------------------

with open(
    "data/processed/vulnerabilities.json",
    "r",
    encoding="utf-8"
) as f:
    vulnerabilities = json.load(f)


# --------------------------------------------------
# 2. Create embedding model
# --------------------------------------------------

print("Loading embedding model...")

model = SentenceTransformer(
    "all-MiniLM-L6-v2"
)

print("Embedding model loaded.")


# --------------------------------------------------
# 3. Create ChromaDB
# --------------------------------------------------

client = chromadb.PersistentClient(
    path="data/chroma"
)

collection = client.get_or_create_collection(
    name="vulnerabilities"
)


# --------------------------------------------------
# 4. Convert CVEs into searchable documents
# --------------------------------------------------

documents = []
ids = []
metadatas = []


for vulnerability in vulnerabilities:

    cve_id = vulnerability["cve_id"]

    severity = vulnerability["cvss"].get("severity")
    score = vulnerability["cvss"].get("score")

    description = vulnerability.get(
        "description",
        ""
    )

    products = []

    for affected_product in vulnerability.get(
        "affected_products",
        []
    ):

        vendor = affected_product.get(
            "vendor",
            ""
        )

        product = affected_product.get(
            "product",
            ""
        )

        products.append(
            f"{vendor} {product}"
        )

    product_text = ", ".join(products)

    document = f"""
CVE: {cve_id}

Affected Products:
{product_text}

Severity:
{severity}

CVSS Score:
{score}

Description:
{description}
"""

    documents.append(document)
    ids.append(cve_id)

    metadatas.append({
        "cve_id": cve_id,
        "severity": severity or "UNKNOWN",
        "score": str(score) if score is not None else "N/A"
    })


# --------------------------------------------------
# 5. Generate embeddings
# --------------------------------------------------

print(
    f"Creating embeddings for {len(documents)} vulnerabilities..."
)

embeddings = model.encode(
    documents,
    show_progress_bar=True
)

print("Embeddings created.")


# --------------------------------------------------
# 6. Store in ChromaDB
# --------------------------------------------------

print("Storing vulnerabilities in ChromaDB...")

collection.upsert(
    ids=ids,
    documents=documents,
    embeddings=embeddings.tolist(),
    metadatas=metadatas
)

print("\nRAG database created successfully.")

print(
    "Total vulnerabilities stored:",
    collection.count()
)

print(
    "Database location: data/chroma"
)