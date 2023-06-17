using FluentValidation;
using XBoilerPlate.Dtos;

namespace XBoilerPlate.Validators;
public class UserLoginValidator : AbstractValidator<UserLoginDto>
{
    public UserLoginValidator()
    {
        RuleFor(x => x.Username).NotEmpty();
        RuleFor(x => x.Password).NotEmpty();
    }
}