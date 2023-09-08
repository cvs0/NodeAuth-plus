# NodeAuth+

NodeAuth+ is a secure user authentication system built using Express.js, Passport.js, and various security headers. This template includes features such as password hashing, rate limiting, security headers, and input validation.

## Features

- User authentication with Passport.js and bcrypt for password hashing.
- Rate limiting to prevent abuse of the API.
- Implementation of essential security headers to protect against common web vulnerabilities.
- Input validation and sanitization using express-validator to prevent SQL injection and XSS attacks.
- Easily customizable styles for a login and dashboard page.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Node.js and npm installed on your machine.
- Basic knowledge of Express.js, Passport.js, and web security concepts.

## Getting Started

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/cvs0/NodeAuth-plus.git
   ```
2. cd Navigate to the project directory:
    ```bash
    cd NodeAuth-plus
    ```
3. Install the required dependencies:
    ```bash
    npm install
    ```
4. Customize the configuration in the config.js file according to your project requirements.
5. Create a users.json file to store user data.
6. Start the application:
    ```bash
    npm start
    ```

## Usage

* The login page is accessible at `/login`. You can customize the styles and content in the `GET /login` route handler.
* Users can log in with their credentials, and successful authentication redirects them to the dashboard.
* The dashboard is accessible at `/dashboard`. You can customize the styles and content in the `GET /dashboard` route handler.
* Users can log out by accessing `/logout`.

## Security Headers

NodeAuth+ includes the following security headers to enhance the security of your application:

* `X-Frame-Options`: Set to `DENY` to prevent your site from being embedded in an iframe on another site.
* `X-Content-Type-Options`: Set to `nosniff` to prevent browsers from interpreting files as something else than declared by the content type.
* `Content Security Policy (CSP)`: Define a CSP header to mitigate XSS attacks by specifying which sources of content are allowed to be loaded. You can customize this header in the `helmet` configuration in `index.js`.
* `Strict-Transport-Security`: Helps ensure that your application is accessed over HTTPS only.
* `Referrer-Policy`: Set to `same-origin` to control the referrer information sent with requests.
* `Permitted Cross-Domain Policies`: Set to `none` to prevent the use of cross-domain policies.
* `Expect-CT`: Enforces Certificate Transparency checks for HTTPS connections.

## Command Line Interface (CLI)

NodeAuth+ provides a Command Line Interface (CLI) tool that allows you to add new users to your authentication system. To use the CLI, follow these steps:

1. Open your terminal or command prompt.

2. Navigate to the project directory where NodeAuth+ is located.

3. Use the following command to add a new user:
    ```bash
   node cli.js add-user --username <username> --password <password>
   ```

   example:
   ```bash
   node cli.js add-user --username cvs0 --password secret_password
   ```

The CLI will securely hash the provided password and add the new user to the authentication system and you will recieve a message indicating if it was successful.

## License

This project is licensed under the ISC License.