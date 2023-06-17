namespace XBoilerPlate.Dtos
{
    public record UserRegisterDto
    {
        public UserRegisterDto(string username, string email, string phoneNumber, string password, string firstName, string surname)
        {
            Username = username;
            Email = email;
            PhoneNumber = phoneNumber;
            Password = password;
            FirstName = firstName;
            Surname = surname;
        }

        public string Username { get; }
        public string Email { get; }
        public string PhoneNumber { get; }
        public string Password { get; }
        public string FirstName { get; }
        public string Surname { get; }
    }
}