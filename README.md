Sure — here is the `README.md` content in proper Markdown format:

````markdown
# SOC Automation System

This project implements a Security Operations Center (SOC) automation backend using **FastAPI**. It supports automated analysis of packet capture (PCAP) files, threat detection, AI-assisted alert generation, evidence logging, and alert lifecycle management.

## Features

- Upload and analyze PCAP files
- Detect suspicious traffic and potential threats
- AI-generated incident summaries and remediation recommendations
- Exportable evidence and threat data
- Email notifications for high-severity alerts
- REST API endpoints for managing alerts
- In-memory alert storage with JSON backups
- Alert approval and rejection by human analysts
- System health and statistics endpoints

## Tech Stack

- **FastAPI** – REST API framework
- **Pandas** – Data analysis and CSV export
- **AsyncIO** – Concurrency and background tasks
- **UUID** – Unique ID generation
- **Email** – SMTP for alert notifications
- **Custom Modules** – PacketAnalyzer, ThreatDetector, AIAnalyzer

## API Endpoints

### PCAP Analysis

- `POST /analyze/upload`  
  Upload and analyze a PCAP file

- `POST /analyze/path`  
  Analyze a PCAP file from a server path

### Alert Management

- `GET /alerts`  
  Retrieve all generated alerts

- `GET /alerts/{incident_id}`  
  Retrieve a specific alert

- `PUT /alerts/{incident_id}/approve`  
  Approve an alert for escalation or action

- `PUT /alerts/{incident_id}/reject?reason=...`  
  Reject an alert with a reason

### Evidence and Threat Files

- `GET /evidence/{incident_id}`  
  Download CSV evidence file for an alert

- `GET /threats/{incident_id}`  
  Download JSON file of detected threat indicators

### System Monitoring

- `GET /stats`  
  Get summary statistics (alerts, severity breakdown, email status)

- `GET /health`  
  Health check endpoint (implementation pending)

## Installation

```bash
git clone https://github.com/GraceIrungu96/PCAP-Incident-Automation.git
cd soc-automation-backend
pip install -r requirements.txt
````

Configure the following environment variables or constants:

* `GROQ_API_KEY`
* `SMTP_SERVER`
* `SMTP_PORT`
* `SMTP_USERNAME`
* `SMTP_PASSWORD`
* `EVIDENCE_DIR`
* `ALERTS_DIR`
* `STORAGE_DIR`

## Running the Application

```bash
uvicorn main:app --reload
```

Visit `http://127.0.0.1:8000/docs` for interactive API documentation.

## Development Notes

* All alerts are stored in an in-memory dictionary (`alerts_db`) and written to disk as JSON.
* Evidence and threat data are saved as CSV and JSON files respectively.
* Criticality and incident names are heuristically extracted from AI-generated content.
* Uploaded files are deleted after analysis via `BackgroundTasks`.

## Future Improvements

* Persistent database storage (e.g., PostgreSQL)
* Role-based access control for alert approval
* Scheduled cleanup of old evidence files
* Web dashboard for real-time alert monitoring

## License

This project is licensed under the MIT License.

```

Let me know if you'd like me to tailor this for deployment (e.g., Docker, systemd, cloud).
```
