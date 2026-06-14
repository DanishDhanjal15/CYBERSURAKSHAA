# Chapter 5: Results & Discussion

## 5.1 Actual Results 

The developed ScamGuard AI system successfully processes unstructured social media text and executes real-time technical domain tracing. Our dual-engine semantic analysis model is highly capable of classifying complex multilingual messages into Safe, Suspicious, and High-Risk Scam categories. 

The interactive dashboard provides immediate, transparent information regarding both the linguistic threat metrics and the technical domain-age risks. By utilizing visual representations such as the "Traffic Light" indicator, accompanied by a precise breakdown of the confidence scores from Engine A (XGBoost) and Engine B (XLM-RoBERTa), users can easily explore the reasoning behind each classification. The backend data fusion operates efficiently, successfully achieving the overarching objective of providing meaningful security insights for safer digital decision-making.

---

## 5.2 Future Scope

While the current capstone architecture is robust, the project can be structurally improved for enterprise deployment. Future iterations will focus on Model Quantization (exporting PyTorch tensors to ONNX architecture) to reduce computational overhead, allowing the deep learning models to run directly on mobile edge devices with minimal latency.

In addition, integrating a relational database (such as PostgreSQL) would allow for a "Human-in-the-Loop" feedback mechanism. By allowing users to manually flag false positives, the system can dynamically retrain its models over time. Additional future improvements could include direct integration via mobile application keyboards or accessibility services, enabling automatic scanning of SMS or WhatsApp messages natively on the user's phone.

---

## 5.3 Testing

The testing phase was a critical component of development to ensure the system functions accurately and degrades gracefully under stress. The system was rigorously tested across multiple parameters:
*   **Module Testing:** The data ingestion pipeline was tested to ensure it correctly unravels shortened URLs (like `bit.ly`) before querying the WHOIS database.
*   **Inference Accuracy:** Both the XGBoost and XLM-RoBERTa models were tested sequentially to verify that Hindi and Marathi test sets cleanly bypassed English keyword traps and triggered the correct semantic warnings.
*   **Graceful Degradation:** We intentionally offline'd the deep learning models during tests to ensure the backend did not crash. The system successfully caught the exception and correctly relayed a "System Degradation Notice" to the frontend.

The results demonstrated that the backend processes asynchronous requests flawlessly, calculates the mathematically weighted fusion score without errors, and accurately classifies threat sentiment. The React dashboard proved highly usable, maintaining a smooth, responsive interface even during heavy rendering latency.

---

## 5.4 Deployment

Currently, ScamGuard AI is deployed as a decoupled application. The presentation layer utilizes React (via Vite) and Tailwind CSS, making the UI highly responsive and accessible natively through any modern web browser. The application layer is deployed locally utilizing a Python FastAPI server running on Uvicorn, which handles the heavy machine-learning inference.

Because the system decoupled the frontend and backend architectures utilizing REST APIs, it is perfectly suited for scalable cloud deployment. In the future, the backend can easily be encapsulated into Docker containers and orchestrated via Kubernetes on cloud providers like AWS or GCP. This ensures the application remains continuously accessible, highly stable, and secure for thousands of concurrent users attempting to analyze communications in real time.
