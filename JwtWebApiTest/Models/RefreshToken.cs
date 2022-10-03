namespace JwtWebApiTest.Models
{
    public class RefreshToken
    {
        // No best implementation for RefreshToken
        // It's up to the coder
        // Could give the RefrshToken an Id and store all the RefreshToken in Database, then revoke them
        // *if there's a new RefreshToken but the user trying to use the old RefreshToken => something is fishy*
        public string Token { get; set; } = string.Empty;
        public DateTime Created { get; set; } = DateTime.Now;
        public DateTime Expires { get; set; }
    }
}
