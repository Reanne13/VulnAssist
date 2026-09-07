import chromadb
from sentence_transformers import SentenceTransformer


# Load embedding model
print("Loading embedding model...")

model = SentenceTransformer(
    "all-MiniLM-L6-v2"
)


# Connect to existing ChromaDB
client = chromadb.PersistentClient(
    path="data/chroma"
)

collection = client.get_collection(
    name="vulnerabilities"
)


def search_vulnerabilities(query, number_of_results=5):

    query_embedding = model.encode(
        [query]
    )[0]

    results = collection.query(
        query_embeddings=[query_embedding.tolist()],
        n_results=number_of_results
    )

    return results


def display_results(results):

    print("\n" + "=" * 60)
    print("RAG SEARCH RESULTS")
    print("=" * 60)

    for i, document in enumerate(
        results["documents"][0],
        start=1
    ):

        metadata = results["metadatas"][0][i - 1]

        print("\n" + "-" * 60)
        print(f"Result {i}")
        print("CVE:", metadata["cve_id"])
        print("Severity:", metadata["severity"])
        print("CVSS:", metadata["score"])
        print("\n", document)


# Only run interactive search when this file is executed directly
if __name__ == "__main__":

    query = input(
        "\nAsk about vulnerabilities: "
    )

    results = search_vulnerabilities(query)

    display_results(results)