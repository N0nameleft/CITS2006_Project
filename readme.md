**To run the docker container:**
`docker build -t rapido_bank . && docker run -it rapido_bank`

The rapido_bank fileystem is located at /opt/rapido_bank/

All the users' (CEO: charles, manager: mathilde, bankers: [maria, santiago, diego], auditor: maxwell) passwords are currently "securepassword". 

### Current Group Permissions 
- The CEO currently has full rwx permissions to all files/directories
- The manager can rx files in the portfolios directory and should be able to rx anything that doesn't belong to the CEO
- The auditor can rx all portfolios and should be able to rx all files
- The bankers can only rwx their own portfolios.

Further adjustments will be necessary, for example all users of the bank can navigate outside of /opt/rapido_bank giving them access to the full Linux filesystem.
