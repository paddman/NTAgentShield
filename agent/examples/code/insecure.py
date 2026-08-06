# Intentionally insecure scanner fixture.
import pickle
import requests

API_KEY = "demo-insecure-api-key"
requests.get("https://example.invalid", verify=False)
object_value = pickle.loads(user_input)
