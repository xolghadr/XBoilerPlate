namespace XBoilerPlate.Dtos
{
    public record UserLoginDto
    {
        public UserLoginDto(string username, string password)
        {
            Username = username;
            Password = password;
        }

        public string Username { get; set; }
        public string Password { get; set; }
    }
}