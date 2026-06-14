# Chapter 4: Design and Implementation

## 4.1 Introduction

This chapter discusses the detailed design and system architecture of ScamGuard AI. The primary goal of the design phase is to translate the conceptual ideas and mathematical algorithms formulated in previous chapters into a structured blueprint that can be implemented as a fully functional software system.

A well-designed architecture ensures high performance, maintainability, and scalability. To illustrate the flow of data, process logic, and structural components of the system, this chapter incorporates three distinct visualizations: a Block Diagram mapping the architecture, a Data Flow Diagram (DFD) showing the lifecycle of user inputs, and a logical Flowchart representing the algorithmic decision-making tree within our Fast API backend.

---

## 4.2 System Block Diagram

The Block Diagram illustrates the high-level components of the ScamGuard AI architecture and how they structurally communicate. It is divided into the Presentation Layer (Frontend), the Application Layer (Backend API), and the Analytics Layer (ML Models and External Validation APIs).

```mermaid
graph TD
    subgraph Presentation Layer
        UI["React & Tailwind Dashboard"]
    end

    subgraph Application Layer
        API["FastAPI Controller (/api/analyze)"]
        FE["Weighted Fusion Engine"]
    end

    subgraph Analytics & ML Layer
        EngA["Engine A: XGBoost (Keywords & Urgency)"]
        EngB["Engine B: XLM-RoBERTa (Semantic Deep Learning)"]
        DOM["Link Checker (Redirection & WHOIS)"]
    end

    subgraph External Services
        WHOIS["Global WHOIS Database"]
    end

    UI -- "Sends Raw Text JSON" --> API
    API -- "Text Data" --> EngA
    API -- "Text Data" --> EngB
    API -- "Extracted URLs" --> DOM
    DOM -- "Query HTTP/Domain" --> WHOIS
    WHOIS -- "Registration Age" --> DOM
    
    EngA -- "Score A" --> FE
    EngB -- "Score B" --> FE
    DOM -- "Domain Risk Penalty" --> FE
    
    FE -- "Final Traffic Light Calculation" --> API
    API -- "Threat Breakdown JSON" --> UI
```

---

## 4.3 Data Flow Diagram (DFD)

The Data Flow Diagram models the specific flow of information exactly as it is processed by the ScamGuard AI backend. It highlights the transition from an unstructured string into mathematical feature vectors and finally into a risk categorization.

```mermaid
graph LR
    User["User / Investor"]
    
    proc1(("Process 1:\nIngestion & Parsing"))
    proc2(("Process 2:\nTechnical Preprocessing"))
    proc3(("Process 3:\nML Threat Inference"))
    proc4(("Process 4:\nRisk Fusion"))

    DS1[("External Database:\nWHOIS / DNS")]
    DS2[("Model Weights:\nXGBoost .pkl & PyTorch .bin")]

    User -- "Raw WhatsApp/Telegram String" --> proc1
    proc1 -- "Unresolved URLs" --> proc2
    proc2 -- "Domain Queries" --> DS1
    DS1 -- "Domain Age" --> proc2
    
    proc1 -- "Cleaned Text" --> proc3
    DS2 -- "Trained ML Weights" --> proc3
    
    proc2 -- "URL Risk Data" --> proc4
    proc3 -- "Model A & Model B Probs." --> proc4
    
    proc4 -- "Structured JSON (Traffic Light)" --> User
```

---

## 4.4 Algorithmic Flowchart

The Process Flowchart demonstrates the internal decision-making logic of the `Analyze` endpoint. It illustrates the exact steps the system takes, including graceful degradation (fallback logic) in case the deep learning models or the WHOIS database fail to respond.

```mermaid
flowchart TD
    Start([Start Analysis]) --> CheckInput{Is Input empty?}
    CheckInput -- Yes --> Err[/Throw 422 Error/]
    CheckInput -- No --> Extract[Extract URLs using Regex]
    
    Extract --> HasURL{Are there URLs?}
    HasURL -- Yes --> HTTP[Resolve Redirects]
    HTTP --> WHOIS[WHOIS Domain Age Query]
    WHOIS --> CalcLink[Calculate Link Risk Penalty]
    HasURL -- No --> EngineA
    CalcLink --> EngineA
    
    EngineA[Engine A: TF-IDF Vectorization & XGBoost Inference] --> CheckEngB{Is XLM-RoBERTa Online?}
    
    CheckEngB -- Yes --> EngineB[Engine B: Subword Tokenization & Semantic Inference]
    CheckEngB -- No --> Fallback[Graceful Degradation: Mark Eng B Offline]
    
    EngineB --> Fusion[Weighted Math Calculation: max Engine A, Engine B]
    Fallback --> Fusion
    
    Fusion --> Combine[Combine NLP Score + Link Penalty]
    Combine --> Color{Assign Traffic Light}
    
    Color -- Score < 40 --> Green[🟢 Safe]
    Color -- Score < 70 --> Yellow[🟡 Suspicious]
    Color -- Score >= 70 --> Red[🔴 High Risk Scam]
    
    Green --> Output([Return JSON Response])
    Yellow --> Output
    Red --> Output
```

---

## 4.5 Implementation Specifications

### 4.5.1 Frontend Implementation
The dashboard is built entirely with **React** mapped via **Vite** for rapid hot-module reloading. It utilizes **Tailwind CSS** for a deep, modern, dark-mode aesthetic. The system interacts with the backend asynchronously using Fetch APIs, capturing `engine_status` booleans to immediately warn users if the backend has entered "Graceful Degradation" mode.

### 4.5.2 Backend Implementation
The API layer is hosted on **FastAPI** utilizing Uvicorn standard. This framework was chosen primarily for its asynchronous capabilities and native Pydantic validation, which ensures raw text injections conform to predefined schemas before ever touching the ML models.

### 4.5.3 Machine Learning Deployment
- **Engine A (XGBoost):** Loaded into application memory via the `pickle` library upon server boot. It runs completely sequentially via CPU processing. 
- **Engine B (XLM-RoBERTa):** Loaded utilizing the `transformers` payload from Hugging Face. To prevent runtime blocking, the tensors are dynamically moved to the GPU parameter using PyTorch (`.to(device)`) if an NVIDIA CUDA environment is active in the deployed container.

## 4.6 Summary

This chapter detailed the structural planning necessary to translate the theoretical ScamGuard AI algorithms into production software. Through the Block Diagram, DFD, and Flowchart, we visually mapped the integration of technical HTTP tracking with advanced semantic modeling. The resulting architecture remains highly robust, capable of maintaining security validations even when external APIs momentarily fail.
