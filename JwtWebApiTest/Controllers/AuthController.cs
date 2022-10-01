using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWebApiTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        // dependency injection ?
        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }

        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {
            // Only work with Authorize available


            // --Use service--
            var userName = _userService.GetMyName();
            return Ok(userName);

            // --Use Controller (not practical)--
            //var userName = User?.Identity?.Name;
            //var userName2 = User.FindFirstValue(ClaimTypes.Name);
            //var role = User.FindFirstValue(ClaimTypes.Role);
            //return Ok(new
            //{
            //    userName,
            //    userName2,
            //    role
            //});
        }

        // Not optimal!
        // Try not to use the controller for all the logic (fat controller)
        // Use repository pattern with authentication service with dependency injection,...
        // token not valid: algorithm is wrong and Claims name is wrong
        // note this is just return the jwt token, haven't verify it yet?

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDTO request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDTO request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("User not found!");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong Password");
            }

            string token = CreateToken(user);
            return Ok(token);
        }

        // step to for implement JWT (JWT work flow)
        // 1. Create password hash method
        //      - Use cryptography algorithm to create passwordSalt and passwordHash; Store in the user object
        //      - When User try to log in, Then "we" will again create the passwordHash with the stored Salt and compare the 2 Hash
        // 2. If login success, create Token with the User and return the token
        // 3. Use the JWT put it in the authorization/authentication header of the HTTP Request
        //          (included role-base authentication (video 2)) (with this you can authorize user to access curtain action)
        // 4. (Optional) Read JWT authorization Claims of a User (better practice)
        //      2 ways: Controller or Service
        //              + Controller is not the best practice
        //              + Use Service in final production

        private string CreateToken(User user)
        {
            // Claims
            // Can put in multiple claims: Username, password, role, ......
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(JwtRegisteredClaimNames.Name, user.Username),  // use this fixed the claimType return link
                new Claim(ClaimTypes.Role, "Admin")  // Testing: change between "{any role}" or "Admin"
                // reasons docs: https://social.msdn.microsoft.com/Forums/en-US/ec2ecd60-43ef-48c2-bfdc-664095ec61ba/claimtypes-value-is-different-than-what-it-seems?forum=aspsecurity
                // backward compatibility reason: https://stackoverflow.com/questions/50012155/jwt-claim-names
            };

            // Key
            // Note: doesn't have to store in controller or appsettings.json (place it some where more secure in real product)(much have atleast 16 characters)
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            // Signing Credential
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512); // Use HmacSha512 to use correct algorithm (HmacSha512Signature is wrong)

            // Packaging Token
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

    }
}
