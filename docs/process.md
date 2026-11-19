1. Call main() with URL of target site, email address of account holder
2. main initializes the TpmProvider
3. main generates a keypair and SS cert for web server.
3. Main Initializes the EjbcaAcmeProvider with TpmProvider (must be customized to ensure only calls to EJBCA are permitted)
3. main initializes the ACME Sesssion (with URI and EjbcaAcmeProvider)
4. main gets the user keypair from TpmProvider
5. main call login on Session with user Keypair, and accountLocation URL (where does it get this? Discovered or cached?)
6. Session calls connect() on EjbcaProvider
7. EjbcaProvider creates TpmHttpConnector
8. TpmHttpConnector creats TpmSslContext (with User key?) 2 way SSL?
6. Create OrderBuilder on session object, add order for target site URL
7. Send Order to server over session (order.create())
8. Perform Authorization (connect to proxy)
9. periodically check status until certificate delivered or order rejected
10. Install issued certificate on client.
11. Obtain or calculate PKCS11 URL
12. Parse apache configuration to identify appropriate section to update
13. Update config directive to point to new key
14. Restart Apache