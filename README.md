# PortfolioManager
This is the code of managing the portfolio for investors.

# Investment Management System

## Overview

The Investment Management System is a Flask-based web application designed for managing users, companies, investment transactions, and contributions. It leverages MongoDB for data storage and provides a robust API for performing CRUD operations on various collections. The system includes user authentication and role-based access control to ensure secure operations.

## Features

- User authentication with role-based access control.
- CRUD operations for users, companies, investments, and contributions.
- Secure session management with cookie settings for production.
- Responsive API endpoints for managing different data entities.
- Error handling for invalid requests and server issues.

## Technologies Used

- **Flask**: Web framework for building the application.
- **MongoDB**: NoSQL database for storing user and transaction data.
- **Bcrypt**: For hashing passwords.
- **JSON**: For data interchange format.
- **Python**: The programming language used for developing the application.

## Installation

### Prerequisites

- Python 3.x
- MongoDB server running
- Dependencies listed in `requirements.txt` (if available)

### Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```
   
2. **Install required packages**:
   You can install the needed packages using pip:
   ```bash
   pip install Flask pymongo bcrypt
   ```

3. **Setup MongoDB**:
   - Ensure your MongoDB server is running and accessible.
   - Create a MongoDB user with the appropriate permissions for accessing collections.

4. **Configuration**:
   - Create a `setting/config.json` file in your project directory with the following structure:
     ```json
     {
         "SECRET_KEY": "your_secret_key",
         "SESSION_COOKIE_SECURE": false,
         "PM_PORT": 5000,
         "MONGODB_URI": "your_mongodb_uri",
         "DB_NAME": "your_database_name"
     }
     ```
   - Fill in the appropriate values.

## Running the Application

To run the Flask application, execute the following command:
```bash
python app.py
```

The application will start and should be accessible at `http://localhost:<PM_PORT>`.

## API Endpoints

### Authentication

- `POST /authenticateUser`: Authenticate a user with ID and password.
- `POST /signout`: Logout the current user.

### User Management

- `GET /getUsers`: Retrieve a list of users (requires login).
- `POST /addUser`: Add a new user.
- `PUT /updateUser/<user_id>`: Update user details.
- `DELETE /deleteUser/<user_id>`: Delete a user.

### Company Management

- `GET /getCompanies`: Retrieve companies (requires login).
- `POST /addCompany`: Add a new company.
- `PUT /updateCompany/<company_id>`: Update company details.
- `DELETE /deleteCompany/<company_id>`: Delete a company.

### Investment Transactions

- `POST /addInvestment`: Add a new investment transaction.
- `PUT /updateInvestment`: Update an existing investment transaction.
- `GET /getInvestments`: Fetch all investments.
- `DELETE /deleteInvestment/<investment_id>`: Delete an investment transaction.

### Contribution Management

- `POST /addContribution`: Add a new contribution.
- `GET /getContributions`: Retrieve contributions.
- `DELETE /deleteContribution/<contribution_id>`: Delete a contribution.

### Access Management

- `GET /getAuthCollects`: Retrieve authentication access collections (requires login).
- `POST /addAuthCollect`: Add a new auth collect.
- `PUT /updateAuthCollect/<auth_id>`: Update an auth collect.
- `DELETE /deleteAuthCollect/<auth_id>`: Delete an auth collect.

## Security Note

- Ensure to configure `SECRET_KEY` and `SESSION_COOKIE_SECURE` properly in production.
- Use HTTPS in production to secure data transmission.

## Contribution

Contributions are welcome! Please open issues or submit pull requests for improvements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

## Support

For any inquiries or support, please reach out via the issues tab in the GitHub repository.
