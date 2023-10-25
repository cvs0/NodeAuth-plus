# NodeAuth+

NodeAuth+ is a secure user authentication system built using Express.js, Passport.js, and various security headers. This template includes features such as password hashing, rate limiting, security headers, and input validation.

## Features

- User authentication with Passport.js and bcrypt for password hashing / salting.
- Rate limiting to prevent abuse of the API.
- Implementation of essential security headers to protect against common web vulnerabilities.
- Easily customizable styles for a login and dashboard page.
- Frequently updated to fix bugs / vulnerabilities that arise.
- IP Blacklist system.
- Lengthy configuration.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Node.js and npm installed on your machine.
- Basic knowledge of Express.js, Passport.js, and web security concepts.
- All of the libaries we used in this project.

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

4. Use the following command to delete a user:
    ```bash
    node cli.js delete-user --username <username>
    ```

    example:
    ```bash
    node cli.js delete-user --username admin
    ```

5. Use the following command to list users:
    ```bash
    node cli.js list-users
    ```

All Commands:
* add-user
* delete-user
* list-users
* help


The CLI will securely hash the provided password and add the new user to the authentication system and you will recieve a message indicating if it was successful.

## Legal Compliance

### Privacy Policy

NodeAuth-Plus is committed to safeguarding your privacy. Our privacy policy explains how we collect, use, and protect your personal information. By using this project, you consent to the practices outlined in our [Privacy Policy](/privacy-policy).

### Terms of Service

By accessing or using this project, you agree to comply with our [Terms of Service](/terms-of-service). These terms govern your use of the site and outline your responsibilities and obligations.

### Cookie Policy

We use cookies on this project. Our [Cookie Policy](/cookie-policy) provides information about our use of cookies and your options regarding their acceptance.

### Accessibility

We are dedicated to making our project accessible to all users. We adhere to [Web Content Accessibility Guidelines (WCAG)](https://www.w3.org/WAI/standards-guidelines/wcag/), ensuring that everyone can access and enjoy our content.

### DMCA Compliance

We respect intellectual property rights. If you believe your copyright is being infringed on our project, please follow our [DMCA Policy](/dmca-policy) to report copyright violations.

### Compliance with GDPR

If you are a resident of the European Union, our website complies with the General Data Protection Regulation ([GDPR](https://gdpr-info.eu/)). Please review our [GDPR Compliance](/gdpr-compliance) to understand your rights and our data protection practices.

### CCPA Compliance

If you are a resident of California, our project complies with the California Consumer Privacy Act ([CCPA](https://oag.ca.gov/privacy/ccpa)). Learn more about your privacy rights and our CCPA compliance in our [CCPA Compliance Statement](/ccpa-compliance).

### Data Protection Officer (DPO)

NodeAuth-Plus has appointed a Data Protection Officer (DPO) to oversee data protection activities and ensure compliance with relevant regulations. For inquiries related to data protection, you can contact our DPO at [DPO Email Address].

### Consult Legal Counsel

The legal landscape is complex and evolving. We strongly recommend consulting with legal counsel to ensure full compliance with all applicable laws and regulations.

## License

This project is licensed under the ISC License.