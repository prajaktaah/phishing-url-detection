Overview

PhishPhry is a browser-based security tool that classifies URLs in real time to detect potentially malicious or unsafe websites using a machine learning model.

It helps users make safer browsing decisions by analyzing links instantly before interaction.

Problem Statement

Users are frequently exposed to phishing websites and malicious URLs through emails, ads, and social media. Most users cannot manually identify these threats.

This project solves the problem by providing real-time URL classification using machine learning, improving browsing safety.

Key Features
Real-time URL classification in browser
Machine learning-based phishing detection
Flask backend API for model inference
Chrome extension integration for instant predictions
Lightweight and fast response system
Tech Stack
Python
Flask
Machine Learning (Scikit-learn)
JavaScript (Chrome Extension)
HTML/CSS
Pandas, NumPy
How It Works
User opens a webpage or clicks a link
URL is captured by the Chrome extension
Extension sends URL to Flask API
ML model analyzes URL features
Response returned: Safe / Phishing
User is alerted in real time
Machine Learning Approach
Feature extraction from URLs (length, special characters, domain patterns, etc.)
Classification model trained on labeled phishing dataset
Predicts probability of malicious intent

Business / Real-World Impact
Helps prevent phishing attacks and data theft
Enhances browser security for everyday users
Can be extended to enterprise cybersecurity systems
Useful for email filtering and fraud detection systems
Future Improvements
Improve model accuracy with deep learning
Add blacklist/whitelist URL database
Deploy as SaaS security API
Integrate with email security systems
Author

Prajakta Kambli
BSc Data Science

Purpose

Built as a cybersecurity-focused ML project demonstrating skills in machine learning, API development, and browser extension integration.
