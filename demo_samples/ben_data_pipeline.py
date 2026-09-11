import csv
from statistics import mean

def load_scores(path):
    with open(path, newline="") as f:
        return [float(r["score"]) for r in csv.DictReader(f)]

def summarize(rows):
    return {"n": len(rows), "avg": round(mean(rows), 2) if rows else 0}
