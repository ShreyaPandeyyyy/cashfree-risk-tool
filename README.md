# Cashfree Risk Tool

A lightweight Website Risk Analysis Tool that crawls a website and evaluates potential trust or security risks.
It extracts useful signals (emails, phones, links, policies, etc.) and computes a risk score and trust score to help identify suspicious websites.

## Live Demo

Dashboard:
https://cashfree-risk-tool.onrender.com/dashboard.html

GitHub Repository:
https://github.com/ShreyaPandeyyyy/cashfree-risk-tool

## Overview

This tool analyzes a given website URL and generates a structured report that includes:

- Extracted emails
- Extracted phone numbers
- Total number of links
- Detection of privacy policy
- Detection of terms of service
- Suspicious domain checks
- Redirect behavior
- Presence of social links
- A calculated Risk Score
- A calculated Trust Score

The goal is to quickly assess whether a website might be safe, suspicious, or potentially risky.

## Features

- Website crawling and content extraction
- Email and phone number detection
- Link analysis
- Suspicious domain pattern detection
- Privacy policy / Terms of service detection
- Risk scoring engine
- Trust scoring engine
- Simple interactive dashboard

## Tech Stack

### Backend

- Node.js

- Express.js

### Frontend

- HTML

- JavaScript

### Deployment

- Render (Web Service)

## Project Structure

cashfree-risk-tool
│
├── crawler.js # Crawls website and extracts data
├── domainCheck.js # Checks suspicious domains
├── externalCheck.js # External signal checks
├── riskRules.js # Defines risk evaluation rules
├── riskScore.js # Calculates risk and trust score
├── server.js # Express API server
│
├── public/
│ └── dashboard.html # Frontend dashboard
│
├── package.json
└── README.md

## How It Works

1. User enters a website URL in the dashboard.
2. The backend crawler fetches the website content.
3. Extracted signals are evaluated through risk rules.
4. A scoring engine calculates:
- Risk Score
- Trust Score
5. Results are displayed in the dashboard.

## Running Locally

Clone the repository

git clone https://github.com/ShreyaPandeyyyy/cashfree-risk-tool.git

Navigate to the project

cd cashfree-risk-tool

Install dependencies

npm install

Start the server

node server.js

Open in browser

http://localhost:3000/dashboard.html

## API Endpoint

POST /analyze

Example request body

{
"url": "https://example.com"
}

Response includes

- emails
- phones
- totalLinks
- rules triggered
- riskScore
- trustScore
- riskLevel

## Example Output

Risk Score: 32
Trust Score: 68
Risk Level: Medium

Signals Detected:

- No privacy policy
- Suspicious domain pattern
- Few external links

 ## Deployment

The project is deployed using Render.

Live URL
https://cashfree-risk-tool.onrender.com/dashboard.html

## Future Improvements

- SSL certificate validation
- WHOIS domain age detection
- Malware blacklist checks
- More advanced scoring model
- Better UI visualization
