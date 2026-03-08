# Merchant Risk Analysis Tool

This project is a Node.js based risk analysis tool designed to evaluate merchant websites for potential fraud signals before enabling payment processing.

The system crawls a merchant website, extracts key trust signals, evaluates multiple risk rules, and generates a risk score along with explanations.

## Features

- Website crawling and content extraction
- Fraud signal detection (suspicious keywords, hidden elements, iframes)
- Domain intelligence checks (domain age, suspicious TLDs)
- Contact and legal compliance checks
- External reputation checks
- Risk scoring engine
- Dashboard to visualize risk signals

## Tech Stack

- Node.js
- Express.js
- Axios
- Cheerio
- HTML/CSS

## How it works

1. User submits a merchant website URL
2. The crawler extracts website signals
3. Risk rules evaluate fraud indicators
4. A risk score and trust score are generated
5. The dashboard displays detected risk signals

## Purpose

This tool demonstrates how payment companies can automate merchant onboarding risk analysis by identifying suspicious websites before enabling payment processing.
