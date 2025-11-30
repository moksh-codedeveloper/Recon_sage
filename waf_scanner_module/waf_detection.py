import httpx
url = "https://youtube.com/"

resp = httpx.get(url)

for key, value in dict(resp.headers).items():
    print(f"This is the headers :- {key} - {value}")