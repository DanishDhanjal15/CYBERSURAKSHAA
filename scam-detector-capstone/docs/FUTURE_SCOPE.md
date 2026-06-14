# 🔮 Future Scope & Scalability

While ScamGuard AI successfully proves the viability of multilingual threat detection on edge/local hardware, transitioning this solution into an enterprise-grade corporate environment requires the following architectural evolutions.

---

## 1. Model Quantization and Inference Optimization
**Goal:** Reduce latency and memory footprint to deploy on low-compute edge servers.
* **ONNX Runtime:** Export the PyTorch XLM-RoBERTa model into ONNX format.
* **Quantization:** Apply dynamic INT8 quantization to reduce the model size from ~1.1GB down to ~300MB, drastically decreasing inference time on CPU endpoints without a massive drop in the 95.31% accuracy threshold.

## 2. Relational Database & Human-in-the-Loop Integration
**Goal:** Continual learning from False Positives and False Negatives.
* **PostgreSQL:** Integrate a robust SQL database (e.g., PostgreSQL with SQLAlchemy ORM) to log historical queries, resulting scores, and user IDs.
* **Feedback Loop:** Implement "Report Mistake" buttons on the frontend. If a user flags a Yellow message as a definitive Scam, the data is pushed to an S3 bucket for the next batch fine-tuning of the XGBoost and RoBERTa models.

## 3. Enterprise Deployment Pipeline
**Goal:** High availability, auto-scaling, and platform independence.
* **Docker Containerization:** Create `Dockerfile`s for both the Vite Frontend and the FastAPI Backend.
* **Kubernetes (K8s):** Deploy the containers onto a managed cloud service (like AWS EKS or GCP GKE).
* **Load Balancing:** Spin up multiple replicas of the FastAPI backend to handle thousands of concurrent analysis requests per second, typical for a social media ingestion API.
