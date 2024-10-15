// Controllers/UsersController.cs

using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public class UsersController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public UsersController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] UserLoginDto userDto)
    {
        // Authenticate the user (check credentials, omitted for brevity)
        var user = AuthenticateUser(userDto); // Returns a User object if credentials are valid

        if (user == null)
        {
            return Unauthorized(); // If authentication fails
        }

        var token = GenerateJwtToken(user);
        return Ok(new { token });
    }

    private string GenerateJwtToken(User user)
    {
        // Create the token handler
        var tokenHandler = new JwtSecurityTokenHandler();

        // Create a secret key using the JWT key from configuration
        var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);

        // Define the token descriptor, including claims and signing credentials
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),  // Token ID
                new Claim(ClaimTypes.Name, user.Username),  // Username claim
                new Claim("role", user.Role)  // User role claim
            }),
            Expires = DateTime.UtcNow.AddHours(2),  // Token expiration
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"],
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)  // Sign the token with the secret key
        };

        // Generate the token
        var token = tokenHandler.CreateToken(tokenDescriptor);

        // Return the serialized token
        return tokenHandler.WriteToken(token);
    }
}
[HttpPost("register")]
public async Task<IActionResult> Register([FromBody] RegisterModel model)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);

    var userExists = await _userManager.FindByNameAsync(model.Username);
    if (userExists != null)
        return StatusCode(StatusCodes.Status500InternalServerError, "User already exists!");

    var user = new ApplicationUser()
    {
        UserName = model.Username,
        Email = model.Email,
    };

    var result = await _userManager.CreateAsync(user, model.Password);
    if (!result.Succeeded)
        return StatusCode(StatusCodes.Status500InternalServerError, "User creation failed! Please check user details and try again.");

    return Ok("User created successfully!");
}

[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginModel model)
{
    var user = await _userManager.FindByNameAsync(model.Username);
    if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
    {
        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            expires: DateTime.Now.AddHours(3),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );

        return Ok(new
        {
            token = new JwtSecurityTokenHandler().WriteToken(token),
            expiration = token.ValidTo
        });
    }
    return Unauthorized();
}

