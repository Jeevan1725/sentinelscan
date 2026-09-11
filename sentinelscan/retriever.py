import json
import math
import re
from pathlib import Path

_SEED_PATH = Path(__file__).parent / "data" / "attack_seed.json"


class TfidfRetriever:
    """Pure-python TF-IDF retriever. Zero dependencies, fully offline."""

    def __init__(self):
        self.docs = []
        self.doc_tf = []
        self.idf = {}
        self._tokenize = lambda t: re.findall(r"[a-z0-9_.\-]+", t.lower())

    def _load_seed(self):
        if not self.docs:
            for d in json.loads(_SEED_PATH.read_text(encoding="utf-8")):
                self.docs.append(d)
            self._build()

    def _build(self):
        df = {}
        self.doc_tf = []
        for d in self.docs:
            toks = self._tokenize(d["name"] + " " + d["text"])
            tf = {}
            for t in toks:
                tf[t] = tf.get(t, 0) + 1
            self.doc_tf.append(tf)
            for t in tf:
                df[t] = df.get(t, 0) + 1
        n = len(self.docs)
        self.idf = {t: math.log(1 + n / c) for t, c in df.items()}

    def search(self, query, k=3):
        self._load_seed()
        qtf = {}
        for t in self._tokenize(query):
            qtf[t] = qtf.get(t, 0) + 1
        qvec = {t: c * self.idf.get(t, 0.0) for t, c in qtf.items()}
        qn = math.sqrt(sum(v * v for v in qvec.values())) or 1.0
        scored = []
        for i, dtf in enumerate(self.doc_tf):
            dot = sum(qvec.get(t, 0) * dtf.get(t, 0) * self.idf.get(t, 0) for t in qvec)
            dn = math.sqrt(sum((c * self.idf.get(t, 0)) ** 2 for t, c in dtf.items())) or 1.0
            sim = dot / (qn * dn)
            if sim > 0:
                scored.append((sim, i))
        scored.sort(reverse=True)
        out = []
        for sim, i in scored[:k]:
            d = self.docs[i]
            out.append({"technique_id": d["id"], "technique_name": d["name"],
                        "score": round(sim, 3),
                        "evidence_text": d["text"][:220] + "..."})
        return out


class ChromaRetriever:
    """Optional Chroma vector store. Used automatically if installed."""

    def __init__(self):
        import chromadb
        self.client = chromadb.PersistentClient(path="./data/chroma")
        self.col = self.client.get_or_create_collection("attack")
        if self.col.count() == 0:
            seed = json.loads(_SEED_PATH.read_text(encoding="utf-8"))
            self.col.add(ids=[d["id"] for d in seed],
                         documents=[d["name"] + " " + d["text"] for d in seed],
                         metadatas=[{"name": d["name"]} for d in seed])

    def search(self, query, k=3):
        r = self.col.query(query_texts=[query], n_results=k)
        out = []
        for i in range(len(r["ids"][0])):
            out.append({"technique_id": r["ids"][0][i],
                        "technique_name": r["metadatas"][0][i]["name"],
                        "score": round(1 - r["distances"][0][i], 3),
                        "evidence_text": r["documents"][0][i][:220] + "..."})
        return out


def get_retriever():
    # TF-IDF is the primary retriever: deterministic, offline, and tuned for the
    # short keyword-style queries our rules produce. Chroma is available as an
    # optional upgrade (see README) but MiniLM embeddings don't match our queries
    # as reliably as keyword overlap on this corpus.
    return TfidfRetriever(), "tf-idf (built-in index)"
