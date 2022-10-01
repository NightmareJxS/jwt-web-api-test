# Welcome to Jwt-Web-Api-Test Repository
### This is where I test and trying to learn/implement JWT into a web API project

## Step to for implement JWT (JWT work flow)
1. Create password hash method
    - Use cryptography algorithm to create passwordSalt and passwordHash; Store in the user object
    - When User try to log in, Then "we" will again create the passwordHash with the stored Salt and compare the 2 Hash
2. If login success, create Token with the User and return the token
3. Use the JWT put it in the authorization/authentication header of the HTTP Request
        (included role-base authentication (video 2)) (with this you can authorize user to access curtain action)
4. (Optional) Read JWT authorization Claims of a User (better practice)
    2 ways: Controller or Service
        + Controller is not the best practice
        + Use Service in final production