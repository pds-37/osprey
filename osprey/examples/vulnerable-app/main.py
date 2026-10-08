from fastapi import FastAPI
import uvicorn
import requests

app = FastAPI(title="Vulnerable Demo Microservice")

@app.get("/")
def read_root():
    return {"message": "Welcome to Vulnerable Demo Service"}

@app.get("/proxy")
def proxy_query(url: str):
    resp = requests.get(url, timeout=5)
    return {"status": resp.status_code, "data": resp.text[:100]}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080)
