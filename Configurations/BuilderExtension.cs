using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using XBoilerPlate.Models;

namespace XBoilerPlate.Configurations;

public static class BuilderExtensions
{
    public static IServiceCollection AddAutenticationConfiguration(this WebApplicationBuilder builder)
    {

        builder.Services.AddIdentity<UserModel, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        builder.Services.Configure<IdentityOptions>(options =>
                    {
                        options.Password.RequiredLength = 8;
                        options.Password.RequireDigit = true;
                        options.Password.RequireLowercase = true;
                        options.Password.RequireUppercase = true;
                        options.Password.RequireNonAlphanumeric = false;
                        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                        options.Lockout.MaxFailedAccessAttempts = 5;
                    });

        var jwtAppSettingOptions = builder.Configuration.GetSection(nameof(JwtIssuerOptions)) ?? throw new ArgumentNullException(nameof(JwtIssuerOptions));
        builder.Services.Configure<JwtIssuerOptions>(options => jwtAppSettingOptions.Bind(options));


        var _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtAppSettingOptions.GetValue<string>(nameof(JwtIssuerOptions.SecretKey))));
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _signingKey,
            ValidIssuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)],
            ValidAudience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)],
            ClockSkew = TimeSpan.Zero,
            NameClaimType = "unique_name",
            // RoleClaimType = ClaimTypes.Role
        };

        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.Audience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)];
                options.ClaimsIssuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)];
                options.TokenValidationParameters = tokenValidationParameters;
            });

        return builder.Services;
    }
}
