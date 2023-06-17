using System.Text;
using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using XBoilerPlate.Configurations;
using XBoilerPlate.Models;
using XBoilerPlate.Validators;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
if (builder.Environment.IsDevelopment())
    builder.Configuration.AddJsonFile("appsettings.Development.json", optional: false, reloadOnChange: true);
if (builder.Environment.IsProduction())
    builder.Configuration.AddJsonFile("appsettings.Production.json", optional: false, reloadOnChange: true);

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));


builder.Services.AddControllers();

builder.Services.AddApiVersioning(options =>
{
    // Set default API version to 1.0
    options.DefaultApiVersion = new ApiVersion(1, 0);
    // Specify the possible API versions
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
});

builder.AddAutenticationConfiguration().AddAuthorization();

builder.Services.AddFluentValidationAutoValidation()
    .AddValidatorsFromAssemblyContaining<UserLoginValidator>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

if (builder.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    // Redirect all HTTP requests to HTTPS
    app.UseHttpsRedirection();

    // Set HSTS header to ensure browsers always use HTTPS
    app.UseHsts();
}


app.UseRouting();

// Use authentication middleware
app.UseAuthentication();

// Use authorization middleware
app.UseAuthorization();

// Configure endpoints
app.MapControllers();

app.Run();