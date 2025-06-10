# VulnBlog - Vulnerability Assessment Assignment

## Overview
VulnBlog is a simple blog application built with Flask. This application is designed for educational purposes as part of a vulnerability assessment exercise. Students should analyze the application to identify security vulnerabilities and provide recommendations.

**Created for MIT9804 - Web Development and Web Security Unit, Assessment 2** (Global Higher Education Institute, Adelaide, Australia)


## Setup Instructions

### Installation

1. Clone or download this repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python app.py
   ```

5. Access the application at `http://localhost:5000`

## Features
- User registration and login
- Create and view blog posts
- User profiles
- Comments on posts
- Search functionality
- Admin panel

## Assignment Instructions

### Objective
Identify and document security vulnerabilities in this web application.

### Tasks
1. **Explore the Application**: Use all features as both regular user and admin
2. **Identify Vulnerabilities**: Look for security issues in:
   - Authentication and session management
   - Input validation and sanitization
   - Database interactions
   - Access control
   - Data exposure
   - Configuration

3. **Document Findings**: For each vulnerability found, document:
   - Vulnerability name and type
   - Location in the code
   - Proof of concept (how to exploit it)
   - Risk level (Low/Medium/High/Critical)
   - Remediation recommendations

4. **Write Report**: Submit a professional security assessment report including:
   - Executive summary
   - Detailed findings
   - Risk assessment matrix
   - Prioritized recommendations
   - Code examples of secure implementations

### Testing Accounts
- Regular User: `user@example.com` / `password123`
- Admin User: `admin@vulnblog.com` / `admin123`

### Hints for Students
- Test all input fields
- Check how the application handles different types of data
- Look at URLs and parameters
- Examine cookie contents
- Try accessing resources you shouldn't
- Check error messages
- Review client-side code

## Grading Criteria
- Completeness of vulnerability identification (40%)
- Accuracy of risk assessment (20%)
- Quality of recommendations (20%)
- Report professionalism and clarity (20%)

**Note**: This application contains intentional security vulnerabilities for educational purposes. Do not deploy this application in any production environment.