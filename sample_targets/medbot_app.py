from flask import Flask, request, jsonify

app = Flask(__name__)

ADMIN_TOKEN = "clinic-admin-secret"

@app.route("/chat", methods=["POST"])
def chat():
    """A deliberately vulnerable MedBot demo endpoint."""
    data = request.get_json(silent=True) or {}
    user_prompt = data.get("prompt", "")

    # Intentionally unsafe: untrusted text is concatenated into the AI prompt.
    prompt_sent = "You are a helpful clinic assistant." + "\nUser: " + user_prompt
    return jsonify({"response": "Demo response", "prompt_sent": prompt_sent})


if __name__ == "__main__":
    app.run(debug=True)
