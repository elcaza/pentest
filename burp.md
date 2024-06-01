# Burp
Remember check the principal vectors of attack
+ https://portswigger.net/

# Vectors
1. SQL injection
1. Cross-site scripting
1. Cross-site request forgery (CSRF)
1. Clickjacking
1. DOM-based vulnerabilities
1. Cross-origin resource sharing (CORS)
1. XML external entity (XXE) injection
1. Server-side request forgery (SSRF)
1. HTTP request smuggling
1. OS command injection [OK]
    1. OS command injection, simple case
    1. Blind OS command injection with time delays (||)
    1. Blind OS command injection with output redirection (>)
    1. Blind OS command injection with out-of-band interaction (nslookup)
    1. Blind OS command injection with out-of-band data exfiltration (``)
1. Server-side template injection
1. Path traversal [OK]
    1. File path traversal, simple case
    1. File path traversal, traversal sequences blocked with absolute path bypass
    1. File path traversal, traversal sequences stripped non-recursively (....//)
    1. File path traversal, traversal sequences stripped with superfluous URL-decode (..%252f)
    1. File path traversal, validation of start of path 
    1. File path traversal, validation of file extension with null byte bypass (%00)
1. Access control vulnerabilities
1. Authentication
1. WebSockets
1. Web cache poisoning
1. Insecure deserialization
1. Information disclosure [OK]
    1. Error messages
    1. Debug pages
    1. Backup files
    1. Header authentication bypass via information disclosure (TRACE)
    1. Version control history
1. Business logic vulnerabilities
1. HTTP Host header attacks
1. OAuth authentication
1. File upload vulnerabilities
1. JWT
1. Essential skills
1. Prototype pollution
1. GraphQL API vulnerabilities
1. Race conditions
1. NoSQL injection
1. API testing
1. Web LLM attacks