# pcap-analyzer-backend

> Backend API for the PCAP Network Analyzer — built with pure Node.js, zero dependencies.

## 🚀 Live API
Deployed on Render: `https://pcap-analyzer-backend.onrender.com`

## 📡 Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/pcap/health` | Health check |
| POST | `/pcap/upload` | Upload a `.pcap` file |
| GET | `/pcap/packets?session_id=X` | Get parsed packets (paginated) |
| GET | `/pcap/vulnerabilities?session_id=X` | Vulnerability detection report |
| POST | `/pcap/agent/query` | Natural language query on packets |
| GET | `/pcap/port-intel?query=X` | Port intelligence lookup |

## 🛠 Run Locally

```bash
node index.js
# Server starts on http://localhost:4000
```

## 📦 Dependencies
None. Uses only Node.js built-in modules.

## ☁️ Deploy on Render
1. Push this repo to GitHub
2. Go to Render → Add Web Service
3. Connect this repo
4. Build Command: `echo "No build step needed"`
5. Start Command: `node index.js`
6. Done ✅
