BrandShield AI
Project Overview

BrandShield AI is a brand protection and suspicious profile detection system designed to analyze URLs, domains, social profiles, and mobile application listings. It uses rule-based detection, similarity matching, and heuristic risk scoring to identify potential brand impersonation and suspicious online activity.

The system provides explainable risk classification, detection results, indicators, and recommendations through a dashboard and reports.

System Architecture

The following diagram represents the BrandShield AI system architecture exactly as provided.

!BrandShield AI System Architecture

Architecture Components
1. User / Security Analyst

The user or security analyst initiates the detection process through the BrandShield AI web interface.

2. BrandShield AI Web Interface

Technologies: HTML, CSS, JavaScript, Bootstrap

Provides the user interface for interacting with the BrandShield AI system.

3. Flask Backend

Handles incoming requests and performs input validation before processing the selected detection type.

4. Select Detection Type

The user selects one of the following analysis categories:

URL & Domain Analysis
Social Profile Analysis
Mobile App Listing Analysis
5. URL & Domain Analysis

Performs URL parsing, suspicious domain rule checks, and domain pattern analysis to identify potentially malicious or impersonating domains.

6. Social Profile Analysis

Compares profile names and usernames to identify potential impersonation of registered brands.

7. Mobile App Listing Analysis

Compares application names and developer information to detect potentially suspicious applications.

8. Registered Brand Profiles

Maintains registered brand profile information, official names, and keywords used during the analysis process.

9. RapidFuzz Similarity Matching

Uses RapidFuzz similarity matching to identify names and identifiers that closely resemble registered brand information.

10. Rule-Based Detection Engine

Combines the analysis results and applies detection rules to identify suspicious indicators.

11. Heuristic Risk Scoring

Calculates a risk score ranging from 0 to 100 based on the detection results.

12. Explainable Risk Classification

Classifies the assessed risk into the following categories:

Low
Medium
High

The classification provides an interpretable assessment of the potential risk.

13. Detection Results

Produces the final detection output, including:

Risk score
Indicators
Recommendations
14. SQLite Database

Stores the following information:

Registered brands
Scan history
Detection results
15. Dashboard & Reports

Presents the detection results through a dashboard and reporting interface.

Technologies shown in the architecture: Flask Templates and Chart.js.

16. User Reviews Findings

Allows the user or security analyst to review the findings and evaluate the detection results.

Detection Workflow
The user accesses the BrandShield AI web interface.
The Flask backend receives the request and validates the input.
The user selects a detection category.
The selected analysis module processes the provided information.
Registered brand profiles and similarity matching support the analysis.
The rule-based detection engine evaluates the indicators.
The heuristic risk scoring component calculates a score between 0 and 100.
The explainable risk classification component assigns a Low, Medium, or High risk category.
Detection results, indicators, and recommendations are generated.
The results and scan history are stored in the SQLite database.
The dashboard and reports present the findings for user review.
Technology Stack
Component	Technology
Frontend	HTML, CSS, JavaScript
UI Framework	Bootstrap
Backend	Python, Flask
Similarity Matching	RapidFuzz
Database	SQLite
Dashboard & Charts	Flask Templates, Chart.js
Risk Assessment	Rule-Based Detection and Heuristic Risk Scoring
Core Features
URL and domain analysis
Suspicious domain pattern detection
Social profile name and username comparison
Mobile application name and developer comparison
Registered brand profiles and keyword matching
RapidFuzz similarity matching
Rule-based detection
Heuristic risk scoring from 0–100
Explainable Low, Medium, and High risk classification
Detection indicators and recommendations
SQLite-based scan history and result storage
Dashboard and reports
Project Structure

The following is a suggested project structure based on the architecture. Actual filenames and folders may differ depending on the implementation.

BrandShield-AI/
├── app.py
├── templates/
│   └── dashboard.html
├── static/
│   ├── css/
│   ├── js/
│   └── images/
├── modules/
│   ├── url_domain_analysis.py
│   ├── social_profile_analysis.py
│   ├── mobile_app_analysis.py
│   ├── similarity_matching.py
│   ├── detection_engine.py
│   └── risk_scoring.py
├── database/
│   └── brandshield.db
├── architecture.jpg
├── requirements.txt
└── README.md


Note: This directory structure is illustrative, not a verified representation of the existing source code.

Installation and Execution

The following steps describe a typical Flask setup. Adjust filenames and dependencies to match the actual project.

Prerequisites
Python 3.10 or later
pip
A web browser
1. Clone the Repository
git clone <repository-url>
cd BrandShield-AI

2. Create a Virtual Environment
python -m venv venv


Activate the environment:

Windows

venv\Scripts\activate


Linux / macOS

source venv/bin/activate

3. Install Dependencies
pip install -r requirements.txt


Ensure that the requirements file includes the packages required by the actual application, such as Flask and RapidFuzz.

4. Run the Application

If the Flask entry point is app.py, run:

python app.py


Open the local URL displayed by Flask in your browser.

Database

BrandShield AI uses SQLite to store brand profiles, scan history, and detection results.

The database supports persistence of analysis results so that users can review previous scans and access recorded findings.

Risk Classification

The system uses heuristic risk scoring on a scale of 0–100 and classifies findings into three categories:

Classification	Description
Low	Lower assessed risk based on the applied detection rules
Medium	Potentially suspicious indicators requiring further review
High	Stronger suspicious indicators requiring careful investigation

Exact score thresholds and detection rules depend on the implementation.

Intended Use

BrandShield AI is intended to assist security analysts in identifying potentially suspicious URLs, domains, social profiles, and mobile application listings that may impersonate registered brands.

Detection results should be reviewed alongside additional evidence before making security decisions.

License

Specify the applicable project license here.

Acknowledgements
Flask
Bootstrap
RapidFuzz
SQLite
Chart.js
