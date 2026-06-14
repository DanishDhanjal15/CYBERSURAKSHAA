# Chapter 2: Literature Survey & Proposed Work

## 2.1 Introduction 

In this chapter, a review of existing research and techniques in the context of cybersecurity, spam filtering, and multilingual natural language processing is provided, along with the proposed approach for this project. In this context, the literature survey is based on various studies that have made use of machine learning, deep learning, and infrastructure validation techniques for analyzing digital communications and determining fraudulent intent.

Though considerable progress has been made in cybersecurity, most of the existing methods are found to be based on either strictly English-only keyword matching or exclusively on URL domain blacklists, without a comprehensive method that combines linguistic psychology with technical tracing. Furthermore, the explosion of regional language usage on platforms like WhatsApp has rendered single-language models obsolete. This has given rise to a requirement for a comprehensive method that can handle real-time, multilingual, unstructured information.

To overcome these challenges, the current work proposes an AI-based system that integrates real-time domain age validation with deep semantic analysis of messaging text. This helps in creating an interactive dashboard with visualizations of threat metrics and ensemble model confidence, thus facilitating safer digital navigation. This improves the efficiency, accuracy, and usability of peer-to-peer scam detection.

---

## 2.2 Literature Survey Table

| Sr.No | Title | Author & Year | Limitations | Summary | Methodology & Technologies Used |
|---|---|---|---|---|---|
| 1 | SMS Spam Collection & Filtering | Almeida et al. (2011) | Focuses entirely on English text without deep semantic context. | Establishes baselines for classifying spam vs. ham messages. | Naive Bayes, SVM, NLP |
| 2 | Phishing Web Site Machine Learning | Mohammad et al. (2015) | Relies only on website structure; ignores the social engineering text used to lure users. | Predicts phishing based on URL structure and domain age features. | Machine Learning, WHOIS logic |
| 3 | XGBoost: A Scalable Tree Boosting System | Chen & Guestrin (2016) | Highly dependent on exact feature engineering (e.g., TF-IDF typos). | Introduces gradient boosting framework ideal for sparse textual data. | Ensemble Learning, XGBoost |
| 4 | Attention Is All You Need | Vaswani et al. (2017) | Attention mechanism sequence lengths are computationally bounded. | Establishes the foundational architecture powering Engine B. | Transformers, Self-Attention |
| 5 | Unsupervised Cross-lingual Representation | Conneau et al. (XLM-R) (2019) | Computationally expensive for real-time edge devices without quantization. | Develops XLM-RoBERTa for deep language understanding across 100 languages. | Transformers, Deep Learning |
| 6 | A Hybrid Approach for Phishing URL Detection | Sahingoz et al. (2019) | Did not analyze unprompted conversational chat patterns. | Combines NLP of URL strings and meta-characteristics for phishing detection. | Random Forest, NLP |
| 7 | Scam Detection in Cryptocurrencies | Xia et al. (2020) | Restricted to analyzing only blockchain transaction graph nodes. | Identifies Ponzi schemes and financial anomalies in digital finance operations. | Network Analysis, Machine Learning |
| 8 | Cyberbullying and Hate Speech Detection | Jain et al. (2021) | Primarily focused on toxicity rather than financial manipulation and urgency. | Uses deep learning to detect malicious intent in short social media text. | Neural Networks, Text Mining |
| 9 | Multilingual Spam Filtering using Deep Learning | Gupta et al. (2022) | Lacked technical infrastructure/domain tracing capability. | Classifies spam and deceptive messaging across various Indian languages. | LSTM, Deep Learning |
| 10 | Financial Fraud Detection in WhatsApp | Verma et al. (2023) | Lacked a user-centric dashboard; highly theoretical. | Analyzes forward-chain behavior and pyramid schemes in regional India. | Graph Theory, Social Media Analytics |

*Table 2.1: Literature Survey Table*

---

## 2.3 Problem Definition

Instant messaging applications produce a massive volume of unstructured data daily, serving as the primary medium for viral financial scams and Ponzi schemes. It is virtually impossible to process and moderate such data using traditional human-in-the-loop approaches. It is a highly time-consuming task, and scammers mutate their phrasing faster than manual blacklists can update.

In addition to that, existing threat-detection systems normally only consider technical infrastructure (like blocking known bad URLs) or simple keyword filters (which fail when translated to regional languages like Hindi or Marathi). As a result, there is a critical need for a system that incorporates both technical domain-age validation and deep multilingual semantic analysis for effective, real-time user protection.

---

## 2.4 Feasibility Study

The proposed system is feasible from a technical, economic, and operational point of view. 

From a **technical** point of view, the system is feasible because there are robust, modern frameworks such as Python (FastAPI), React, and Hugging Face Transformers that can be used for rapid development. In addition, there are available libraries such as `python-whois` and `requests` which allow for the easy retrieval of domain registration information and redirect tracking.

**Economically**, it can be said that this project is highly cost-effective. It utilizes open-source machine learning algorithms (XGBoost) and pre-trained Transformer weights (Meta's XLM-RoBERTa), requiring no costly enterprise software licenses. Training was accomplished on free academic cloud tiers (Google Colab T4).

From an **operational** perspective, the system is simple and intuitively user-friendly. The interactive "Traffic Light" dashboard allows for a clear, immediate understanding of message risk without requiring the user to interpret complex probability matrices. This makes it highly practical for real-world use by everyday individuals.

---

## 2.5 Methodology

The methodology used in the project includes a number of key steps. First of all, the user inputs unstructured social media text representing potential forward-chains or financial offers. The backend cleanly parses this data, extracting any embedded URLs and preparing the raw text for linguistic analysis.

The next step in the process is technical preprocessing and tracing. Any extracted URLs undergo HTTP requests to unravel URL shorteners, followed by a WHOIS database query to determine if the underlying domain is newly registered. At this stage, important linguistic features are also tokenized and vectorized via TF-IDF to prepare for machine inference.

Once the data is preprocessed, deep threat analysis is done utilizing a dual-engine architecture. Engine A uses an XGBoost Classifier to identify known scam keyword density and urgency triggers. Simultaneously, Engine B uses a fine-tuned XLM-RoBERTa neural network to comprehend nuanced semantic meaning across English, Hindi, and Marathi. The outputs of these models are then mathematically fused alongside the domain risk penalty to generate a definitive risk score.

Finally, all the data and threat breakdowns are displayed using an interactive dashboard created with the help of React and Tailwind CSS. The data is represented in a visually appealing "Traffic Light" manner—categorizing the message as Red, Yellow, or Green—along with human-readable reasoning to definitively assist the user.

---

## 2.6 Summary

The current chapter has given an overview of the research work done on the topic of cybersecurity, phishing detection, and multilingual sentiment/intent analysis. It also evaluated how feasible the ScamGuard AI architecture is with regard to technical, economic, and operational aspects.

Moreover, the methodology adopted for the project was discussed, which includes URL extraction, transformer-based preprocessing, ensemble semantic analysis, and React visualization. Thus, the chapter provides the architectural background for developing a robust system that integrates technical infrastructure checks with deep learning text analysis for effective threat mitigation.
