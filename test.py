from google import genai

client = genai.Client()

response = client.models.generate_content(
    model="gemini-3.5-flash-lite",
    contents="Explain what a VLAN is in one sentence."
)

print(response.text)