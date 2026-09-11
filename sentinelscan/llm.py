"""
Pluggable LLM layer.

Priority:  Groq (if GROQ_API_KEY set)  >  RuleBased (sovereign, default).
The LLM is used ONLY for the analyst summary text. It never makes verdicts.
"""
import os

from dotenv import load_dotenv
load_dotenv()


class RuleBasedLLM:
    name = "rule-synthesizer (local, sovereign mode)"

    def summarize(self, state):
        dets = state.detections
        if not dets:
            return ("No malicious behaviors were detected by the static-analysis agent. "
                    "Recommend: allow, monitor, or escalate if business context says otherwise.")
        top = sorted(dets.items(), key=lambda kv: -len(kv[1]["evidence"]))[:3]
        parts = [f"- **{b.replace('_', ' ')}** ({len(ev['evidence'])} code evidence hits)"
                 for b, ev in top]
        return ("Static analysis identified the following behavior clusters:\n"
                + "\n".join(parts)
                + "\n\nThese map to known ATT&CK techniques cited below.")


class GroqLLM:
    def __init__(self):
        from groq import Groq
        self.client = Groq(api_key=os.environ["GROQ_API_KEY"])
        self.model = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")
        self.name = f"groq ({self.model})"

    def summarize(self, state):
        prompt = (
            "You are a malware analyst. In <=100 words, summarize for a SOC analyst. "
            "Cite only the facts given - do not invent behaviors.\n"
            f"Detected behaviors: {list(state.detections)}\n"
            f"Risk: {state.risk}\n"
            f"Confidence: {state.confidence:.2f}\n"
            "Return plain prose, no headers, no bullet points."
        )
        r = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=400,
        )
        return r.choices[0].message.content.strip()


def get_llm():
    # Priority 1: Groq (raises if broken — visible during dev, silent in prod)
    if os.environ.get("GROQ_API_KEY"):
        try:
            return GroqLLM()
        except Exception as e:
            print(f"[llm] groq unavailable, using sovereign fallback: {e}")
    # Priority 2: sovereign
    return RuleBasedLLM()