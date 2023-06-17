using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using XBoilerPlate.Dtos;
using XBoilerPlate.Models;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using XBoilerPlate.Configurations;
using Microsoft.Extensions.Options;
using System.Text;
using System.Security.Cryptography;

namespace XBoilerPlate.Controllers;

[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1")]
[Authorize]
public class UsersController : ControllerBase
{
    private readonly UserManager<UserModel> _userManager;
    private readonly SignInManager<UserModel> _signInManager;
    private readonly IOptions<JwtIssuerOptions> _jwtIssuerOptions;

    public UsersController(UserManager<UserModel> userManager, SignInManager<UserModel> signInManager, IOptions<JwtIssuerOptions> jwtIssuerOptions)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtIssuerOptions = jwtIssuerOptions;
    }

    [HttpGet]
    public IActionResult Get()
    {
        var users = _userManager.Users.ToList();

        return Ok(users);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> Get(string id)
    {
        var user = await _userManager.FindByIdAsync(id);

        if (user == null)
        {
            return NotFound();
        }

        return Ok(user);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] UserRegisterDto model)
    {
        var user = new UserModel
        {
            UserName = model.Username,
            Email = model.Email,
            FirstName = model.FirstName,
            Surname = model.Surname,
            PhoneNumber = model.PhoneNumber
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok();
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(string id, [FromBody] UserRegisterDto model)
    {
        var user = await _userManager.FindByIdAsync(id);

        if (user == null)
        {
            return NotFound();
        }

        user.Email = model.Email;
        var result = await _userManager.UpdateAsync(user);

        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(string id)
    {
        var user = await _userManager.FindByIdAsync(id);

        if (user == null)
        {
            return NotFound();
        }

        var result = await _userManager.DeleteAsync(user);

        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok();
    }

    [AllowAnonymous]
    [HttpPost("signIn")]
    public async Task<IActionResult> Login(UserLoginDto dto)
    {
        var user = await _userManager.FindByNameAsync(dto.Username);
        if (user is null)
            return Unauthorized();

        var check = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, true);
        if (check.Succeeded)
        {
            var accessToken = GenerateUserAccessToken(user);
            return Ok(accessToken);
        }
        return Unauthorized();
    }

    private string GenerateUserAccessToken(UserModel user)
    {
        var jwtOptions = _jwtIssuerOptions.Value ?? throw new NullReferenceException(nameof(JwtIssuerOptions));

        // Create claims for the token
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.UserName!),
        };

        string issuer = HttpContext.Request.Host.HasValue? $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host.Value}" : jwtOptions.Issuer;
        string audience = HttpContext.Request.Host.HasValue ? $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host.Value}" : jwtOptions.Audience;

        // var tokenDescriptor = new SecurityTokenDescriptor
        // {
        //     AdditionalHeaderClaims = new Dictionary<string, object> { { "kid", Guid.NewGuid() } },
        //     Subject = new ClaimsIdentity(claims),
        //     NotBefore = jwtOptions.NotBefore,
        //     Audience = audience,
        //     IssuedAt = jwtOptions.IssuedAt,
        //     Issuer = issuer,
        //     CompressionAlgorithm = "gzip",
        //     Expires = jwtOptions.Expiration,
        //     SigningCredentials = jwtOptions.SigningCredentials,
        // };

        // var rsa = RSA.Create(4096);
        // var rsaSecurityKey = new RsaSecurityKey(rsa)
        // {
        //     KeyId = Guid.NewGuid().ToString()
        // };
        // tokenDescriptor.SigningCredentials = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSsaPssSha512);

        JwtHeader header = new JwtHeader(jwtOptions.SigningCredentials)
        {
            { "kid", Guid.NewGuid() }
        };
        JwtPayload payload = new(issuer, audience, claims, jwtOptions.NotBefore, jwtOptions.Expiration);
        var jwt = new JwtSecurityToken(header, payload);
        var jwtSrtring = new JwtSecurityTokenHandler().WriteToken(jwt);
        return jwtSrtring;
    }
}
